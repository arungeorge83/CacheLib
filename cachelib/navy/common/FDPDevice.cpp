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
  nvmeData_ = readNvmeInfo(fd);
  initializeFDP(fd);
  XLOG(INFO)<< "Creating FdpDevice on fd :" << fd;
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

void FdpDev::initializeFDP(int fd) {
  nextPIDIdx_ = kDefaultPIDIdx;

  Buffer buffer = nvmeFdpStatus(fd);
  if (!buffer.isNull()) {
    struct nvme_fdp_ruh_status *ruh_status =
      reinterpret_cast<struct nvme_fdp_ruh_status*>(buffer.data());

    if (ruh_status->nruhsd) {
      maxPIDIdx_ = ruh_status->nruhsd - 1;
      for (uint16_t i = 0; i <= maxPIDIdx_; ++i) {
        placementIDs_[i] = ruh_status->ruhss[i].pid;
      }
    }
  }
  XLOG(INFO)<< "Creating NvmeFdpDevice, fd :"<< fd<<" Num of PID: "
            <<maxPIDIdx_ + 1<<" First PID: "<<placementIDs_[0]
            <<" Last PID: "<<placementIDs_[maxPIDIdx_];
}

int FdpDev::nvmeIOMgmtRecv(int fd, uint32_t nsid, void *data,
                  uint32_t data_len, uint16_t mos, uint8_t mo) {
  uint32_t cdw10 = (mo & 0xf) | (mos & 0xff << 16);
  uint32_t cdw11 = (data_len >> 2) - 1;

  struct nvme_passthru_cmd cmd = {
    .opcode             = nvme_cmd_io_mgmt_recv,
    .nsid               = nsid,
    .addr               = (uint64_t)(uintptr_t)data,
    .data_len           = data_len,
    .cdw10              = cdw10,
    .cdw11              = cdw11,
    .timeout_ms         = NVME_DEFAULT_IOCTL_TIMEOUT,
  };

  return ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
}

// struct nvme_fdp_ruh_status is a variable sized object; so using Buffer.
Buffer FdpDev::nvmeFdpStatus(int fd) {
  struct nvme_fdp_ruh_status hdr;
  int err;

  // Read FDP ruh status header to get Num_RUH Status Descriptors
  err = nvmeIOMgmtRecv(fd, nvmeData_.nsId(), &hdr, sizeof(hdr), 0,
      NVME_IO_MGMT_RECV_RUH_STATUS);
  if (err) {
    XLOG(ERR)<< "failed to get reclaim unit handle status header";
    return Buffer{};
  }

  auto size = sizeof(struct nvme_fdp_ruh_status) +
            (hdr.nruhsd * sizeof(struct nvme_fdp_ruh_status_desc));
  auto buffer = Buffer(size);

  // Read FDP RUH Status
  err = nvmeIOMgmtRecv(fd, nvmeData_.nsId(), buffer.data(), size, 0,
      NVME_IO_MGMT_RECV_RUH_STATUS);
  if (err) {
    XLOG(ERR)<< "failed to get reclaim unit handle status";
    return Buffer{};
  }

  return buffer;
}

void FdpDev::prepFdpUringCmdSqe(struct io_uring_sqe& sqe, int fd, void* buf,
    size_t size, off_t start, uint8_t opcode, uint8_t dtype, uint16_t dspec,
    NvmeData& nvmeData) {
  uint32_t maxTfrSize = getMaxTfrSize();
  if (maxTfrSize && size > maxTfrSize) {
    throw std::invalid_argument("Exceeds max Transfer size");
  }
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

  char ctrl[NVME_IDENTIFY_DATA_SIZE]; // Identify ctrl data
  struct nvme_passthru_cmd cmd_ctrl = {
    .opcode         = nvme_admin_identify,
    .nsid           = 0,
    .addr           = (uint64_t)(uintptr_t)ctrl,
    .data_len       = NVME_IDENTIFY_DATA_SIZE,
    .cdw10          = NVME_IDENTIFY_CNS_CTRL,
    .cdw11          = NVME_CSI_NVM << NVME_IDENTIFY_CSI_SHIFT,
    .timeout_ms     = NVME_DEFAULT_IOCTL_TIMEOUT,
  };

  int err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd_ctrl);
  if (err) {
    XLOG(ERR)<< "failed to fetch identify ctrl";
    return NvmeData{};
  }

  static constexpr uint16_t kMDTSOffset = 77u;
  uint8_t mdts = (uint8_t)ctrl[kMDTSOffset];
  uint32_t maxTfrSize = (1 << mdts) * getpagesize();

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

  err = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
  if (err) {
    XLOG(ERR)<< "failed to fetch identify namespace";
    return NvmeData{};
  }

  auto lbaShift = (uint32_t)ilog2(1 << ns.lbaf[(ns.flbas & 0x0f)].ds);
  XLOG(INFO) <<"Nvme Device Info, NS Id: " <<namespace_id<<", lbashift: "
             <<lbaShift<<", size: "<<ns.nsze<<", Max Tfr size: "<<maxTfrSize;

  return NvmeData{namespace_id, lbaShift, ns.nsze, maxTfrSize};
}
} // namespace navy
} // namespace cachelib
} // namespace facebook
