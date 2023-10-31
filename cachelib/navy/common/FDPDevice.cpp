/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cachelib/navy/common/FDPDevice.h"

#include <linux/nvme_ioctl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <cstring>
#include <numeric>

namespace facebook {
namespace cachelib {
namespace navy {
enum OpType : uint8_t { INVALID = 0, READ, WRITE };

std::unique_ptr<folly::AsyncBaseOp>
FdpPlacementHandle::prepAsyncIo(int fd, uint8_t opType, void* data,
    uint32_t size, uint64_t offset, void* userdata, bool useIoUring) {
  std::unique_ptr<folly::AsyncBaseOp> asyncOp;

  std::unique_ptr<folly::IoUringOp> iouringCmdOp;
  folly::IoUringOp::Options options;
  options.sqe128 = true;
  options.cqe32 = true;
  iouringCmdOp = std::make_unique<folly::IoUringOp>
                  (folly::AsyncBaseOp::NotificationCallback(), options);

  iouringCmdOp->initBase();
  struct io_uring_sqe& sqe = iouringCmdOp->getSqe();
  if (opType == OpType::READ) {
    fdpDev_.prepReadUringCmdSqe(sqe, fd, data, size, offset);
  } else {
    XDCHECK_EQ(opType, OpType::WRITE);
    fdpDev_.prepWriteUringCmdSqe(sqe, fd, data, size, offset, id());
  }
  asyncOp = std::move(iouringCmdOp);
  asyncOp->setUserData(userdata);
  io_uring_sqe_set_data(&sqe, asyncOp.get());

  return std::move(asyncOp);
}

bool FdpPlacementHandle::prepSyncIo(int fd, uint8_t opType, void* data,
    uint32_t size, uint64_t offset) {
  throw std::runtime_error("Not Implemented.");
}

bool FdpPlacementHandle::verifyResult(ssize_t status, const uint32_t size) {
  // io_uring_cmd returns the success as 0.
  return (status == 0);
}

FdpDev::FdpDev(int fd) {
  // Many NVMe controllers has the tfr size limit. Now use a default value.
  static constexpr uint32_t kMaxTfrSize = 262144u;

  nvmeData_ = readNvmeInfo(fd);
  initializeFDP();

  maxTfrSize_ = kMaxTfrSize;
  XLOG(INFO)<< "Creating FdpDevice on fd :" << fd << ", Tfr size : "
                << maxTfrSize_;
}

std::shared_ptr<PlacementHandle> FdpDev::allocateFdpHandle() {
  uint16_t phndl;

  // Get NS specific Fdp Placement Handle
  if (nextPIDIdx_ <= maxPIDIdx_) {
    phndl = nextPIDIdx_++;
  } else {
    phndl = kDefaultPIDIdx;
  }
  // Get Device specific the Fdp Placement ID for PHNDL
  auto pid = getFdpPID(phndl);

  return std::make_shared<FdpPlacementHandle>(*this, pid);
}

void FdpDev::initializeFDP() {
  maxPIDIdx_ = 7u; // Samsung PM9D3 capability
  nextPIDIdx_ = kDefaultPIDIdx;
}

void FdpDev::prepFdpUringCmdSqe(struct io_uring_sqe& sqe, int fd, void* buf,
    size_t size, off_t start, uint8_t opcode, uint8_t dtype, uint16_t dspec,
    NvmeData& nvmeData) {
  // Clear the SQE entry to avoid some arbitrary flags being set.
  memset(&sqe, 0, sizeof(struct io_uring_sqe));
  sqe.fd = fd;
  sqe.opcode = IORING_OP_URING_CMD;
  sqe.cmd_op = NVME_URING_CMD_IO;

  struct nvme_uring_cmd* cmd = (struct nvme_uring_cmd*)&sqe.cmd;
  if (cmd == nullptr) {
    throw std::invalid_argument("Uring cmd is NULL!");
  }
  memset(cmd, 0, sizeof(struct nvme_uring_cmd));
  cmd->opcode = opcode;

  uint64_t sLba = start >> nvmeData.lbaShift();
  uint32_t nLb  = (size >> nvmeData.lbaShift()) - 1;

  /* cdw10 and cdw11 represent starting lba */
  cmd->cdw10 = sLba & 0xffffffff;
  cmd->cdw11 = sLba >> 32;
  /* cdw12 represent number of lba's for read/write */
  cmd->cdw12 = (dtype & 0xFF) << 20 | nLb;
  cmd->cdw13 = (dspec << 16);
  cmd->addr = (uint64_t)buf;
  cmd->data_len = size;

  cmd->nsid = nvmeData.nsId();
}

void FdpDev::prepReadUringCmdSqe(struct io_uring_sqe& sqe, int fd, void* buf,
    size_t size, off_t start) {
  // Placement Handle is not used for read.
  prepFdpUringCmdSqe(sqe, fd, buf, size, start, nvme_cmd_read, 0, 0, getNvmeData());
}

void FdpDev::prepWriteUringCmdSqe(struct io_uring_sqe& sqe, int fd, void* buf,
    size_t size, off_t start, uint16_t id) {
  static constexpr uint8_t kPlacementMode = 2;

  prepFdpUringCmdSqe(sqe, fd, buf, size, start, nvme_cmd_write,
              kPlacementMode, id, getNvmeData());
}

NvmeData FdpDev::readNvmeInfo(int fd) {
  int namespace_id = ioctl(fd, NVME_IOCTL_ID);
  if (namespace_id < 0) {
    XLOG(ERR)<< "failed to fetch namespace-id, fd "<< fd;
    return NvmeData{};
  }

  struct nvme_id_ns ns;
  struct nvme_passthru_cmd cmd = {
    .opcode         = nvme_admin_identify,
    .nsid           = (uint32_t)namespace_id,
    .addr           = (uint64_t)(uintptr_t)&ns,
    .data_len       = NVME_IDENTIFY_DATA_SIZE,
    .cdw10          = NVME_IDENTIFY_CNS_NS,
    .cdw11          = NVME_CSI_NVM << NVME_IDENTIFY_CSI_SHIFT,
    .timeout_ms     = NVME_DEFAULT_IOCTL_TIMEOUT,
  };

  int err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
  if (err) {
    XLOG(ERR)<< "failed to fetch identify namespace";
    return NvmeData{};
  }

  auto lbaShift = (uint32_t)ilog2(1 << ns.lbaf[(ns.flbas & 0x0f)].ds);
  XLOG(INFO) <<"Nvme Device Info: " <<namespace_id<<" lbashift: "
                      <<lbaShift<<", size: "<<ns.nsze;

  return NvmeData{namespace_id, lbaShift, ns.nsze};
}
} // namespace navy
} // namespace cachelib
} // namespace facebook
