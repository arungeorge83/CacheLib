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

FdpInfo::FdpInfo(int fd) {
  // Many NVMe controllers has the tfr size limit. Now use a default value.
  static constexpr uint32_t kMaxTfrSize = 262144u;

  nvmeData_ = readNvmeInfo(fd);
  initializeFDP();

  maxTfrSize_ = kMaxTfrSize;
  XLOG(INFO)<< "Creating Fdp Device on fd :" << fd << ", Tfr size : "
                << maxTfrSize_;
}

int FdpInfo::allocateFdpHandle() {
  uint16_t phndl;

  // Get NS specific Fdp Placement Handle(PHNDL)
  if (nextPIDIdx_ <= maxPIDIdx_) {
    phndl = nextPIDIdx_++;
  } else {
    phndl = kDefaultPIDIdx;
  }
  // Get Device specific Fdp Placement ID for PHNDL
  auto pid = getFdpPID(phndl);

  return static_cast<int>(pid);
}

void FdpInfo::initializeFDP() {
  maxPIDIdx_ = 7u; // Samsung PM9D3 capability
  nextPIDIdx_ = kDefaultPIDIdx + 1;
}

void FdpInfo::prepFdpUringCmdSqe(struct io_uring_sqe& sqe, int fd, void* buf,
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

void FdpInfo::prepReadUringCmdSqe(struct io_uring_sqe& sqe, int fd, void* buf,
    size_t size, off_t start) {
  // Placement Handle is not used for read.
  prepFdpUringCmdSqe(sqe, fd, buf, size, start, nvme_cmd_read, 0, 0, getNvmeData());
}

void FdpInfo::prepWriteUringCmdSqe(struct io_uring_sqe& sqe, int fd, void* buf,
    size_t size, off_t start, int handle) {
  static constexpr uint8_t kPlacementMode = 2;
  uint16_t id;

  if (handle == -1) {
    id = 0; // Use the default stream
  } else if (handle >= 0) {
    id = static_cast<uint16_t>(handle);
  } else {
    throw std::invalid_argument("Invalid placement identifier!");
  }

  prepFdpUringCmdSqe(sqe, fd, buf, size, start, nvme_cmd_write,
              kPlacementMode, id, getNvmeData());
}

NvmeData FdpInfo::readNvmeInfo(int fd) {
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
