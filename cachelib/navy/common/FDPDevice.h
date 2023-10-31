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

#pragma once

#include "cachelib/navy/common/Device.h"
#include "cachelib/navy/common/Buffer.h"
#include <folly/File.h>
#include <folly/experimental/io/AsyncBase.h>
#include <folly/experimental/io/IoUring.h>
#include <liburing.h>

namespace facebook {
namespace cachelib {
namespace navy {
// Reference: https://github.com/axboe/fio/blob/master/engines/nvme.h
// If the uapi headers installed on the system lacks nvme uring command
// support, use the local version to prevent compilation issues.
#ifndef CONFIG_NVME_URING_CMD
struct nvme_uring_cmd {
  __u8  opcode;
  __u8  flags;
  __u16 rsvd1;
  __u32 nsid;
  __u32 cdw2;
  __u32 cdw3;
  __u64 metadata;
  __u64 addr;
  __u32 metadata_len;
  __u32 data_len;
  __u32 cdw10;
  __u32 cdw11;
  __u32 cdw12;
  __u32 cdw13;
  __u32 cdw14;
  __u32 cdw15;
  __u32 timeout_ms;
  __u32 rsvd2;
};

#define NVME_URING_CMD_IO _IOWR('N', 0x80, struct nvme_uring_cmd)
#define NVME_URING_CMD_IO_VEC _IOWR('N', 0x81, struct nvme_uring_cmd)
#endif /* CONFIG_NVME_URING_CMD */

struct nvme_lbaf {
  __le16 ms;
  __u8   ds;
  __u8   rp;
};

struct nvme_id_ns {
  __le64 nsze;
  __le64 ncap;
  __le64 nuse;
  __u8   nsfeat;
  __u8   nlbaf;
  __u8   flbas;
  __u8   mc;
  __u8   dpc;
  __u8   dps;
  __u8   nmic;
  __u8   rescap;
  __u8   fpi;
  __u8   dlfeat;
  __le16 nawun;
  __le16 nawupf;
  __le16 nacwu;
  __le16 nabsn;
  __le16 nabo;
  __le16 nabspf;
  __le16 noiob;
  __u8   nvmcap[16];
  __le16 npwg;
  __le16 npwa;
  __le16 npdg;
  __le16 npda;
  __le16 nows;
  __le16 mssrl;
  __le32 mcl;
  __u8   msrc;
  __u8   rsvd81[11];
  __le32 anagrpid;
  __u8   rsvd96[3];
  __u8   nsattr;
  __le16 nvmsetid;
  __le16 endgid;
  __u8   nguid[16];
  __u8   eui64[8];
  struct nvme_lbaf  lbaf[16];
  __u8   rsvd192[192];
  __u8   vs[3712];
};

#define NVME_DEFAULT_IOCTL_TIMEOUT 0
#define NVME_IDENTIFY_DATA_SIZE 4096
#define NVME_IDENTIFY_CSI_SHIFT 24
enum nvme_identify_cns {
  NVME_IDENTIFY_CNS_NS        = 0x00,
  NVME_IDENTIFY_CNS_CTRL      = 0x01,
  NVME_IDENTIFY_CNS_CSI_NS    = 0x05,
  NVME_IDENTIFY_CNS_CSI_CTRL  = 0x06,
};

enum nvme_csi {
  NVME_CSI_NVM       = 0,
  NVME_CSI_KV        = 1,
  NVME_CSI_ZNS       = 2,
};

enum nvme_admin_opcode {
  nvme_admin_get_log_page     = 0x02,
  nvme_admin_identify         = 0x06,
  nvme_admin_get_features     = 0x0a,
};

enum nvme_features_id {
  NVME_FEAT_FID_FDP           = 0x1d,
};

enum nvme_cmd_get_log_lid {
  NVME_LOG_LID_FDP_CONFIGS    = 0x20,
};

enum nvme_io_mgmt_recv_mo {
  NVME_IO_MGMT_RECV_RUH_STATUS = 0x1,
};

struct nvme_fdp_ruh_status_desc {
  uint16_t pid;
  uint16_t ruhid;
  uint32_t earutr;
  uint64_t ruamw;
  uint8_t  rsvd16[16];
};

struct nvme_fdp_ruh_status {
  uint8_t  rsvd0[14];
  uint16_t nruhsd;
  struct nvme_fdp_ruh_status_desc ruhss[];
};

enum nvme_io_opcode {
  nvme_cmd_write    = 0x01,
  nvme_cmd_read     = 0x02,
  nvme_cmd_io_mgmt_recv   = 0x12,
  nvme_cmd_io_mgmt_send   = 0x1d,
};

static inline int ilog2(uint32_t i) {
  int log = -1;

  while (i) {
    i >>= 1;
    log++;
  }
  return log;
}

class NvmeData {
 public:
  NvmeData() = default;
  NvmeData& operator=(const NvmeData&) = default;

  explicit NvmeData(int nsId, uint32_t lbaShift, uint64_t nLba,
      uint32_t maxTfrSize)
    : nsId_(nsId), lbaShift_(lbaShift), nLba_(nLba), maxTfrSize_(maxTfrSize) {}

  int nsId() const { return nsId_;}
  uint32_t lbaShift() const { return lbaShift_;}
  uint64_t nLba() const { return nLba_;}
  uint32_t getMaxTfrSize() { return maxTfrSize_; }

 private:
  int nsId_;
  uint32_t lbaShift_;
  uint64_t nLba_;
  uint32_t maxTfrSize_{};
};

class FdpDev;
class FdpPlacementHandle : public PlacementHandle {
 public:
  FdpPlacementHandle(FdpDev& fdpDev, uint16_t id):
            fdpDev_(fdpDev),
            id_(id) {};
  ~FdpPlacementHandle() override = default;

  // Checks whether the id is valid.
  bool valid() override { return id_ != kInvalid; }

  // Get the FdpDev associated with the handle
  FdpDev& getFdpDev() { return fdpDev_; }

  // Returns the fdp placement id for data placement.
  uint16_t id() override { return id_; }

  std::unique_ptr<folly::AsyncBaseOp>
    prepAsyncIo(int, uint8_t, void*, uint32_t, uint64_t, void*, bool) override;

  bool prepSyncIo(int, uint8_t, void*, uint32_t, uint64_t) override;

  bool verifyResult(ssize_t, const uint32_t) override;

 private:
  static constexpr uint16_t kInvalid{~0u & 0xFFFF};
  uint16_t id_{kInvalid};
  FdpDev& fdpDev_;
};

class FdpDev {
 public:
  FdpDev(int fd);

  FdpDev(const FdpDev&) = delete;
  FdpDev& operator=(const FdpDev&) = delete;

  std::shared_ptr<PlacementHandle> allocateFdpHandle();
  uint32_t getMaxTfrSize() { return nvmeData_.getMaxTfrSize(); }
  NvmeData& getNvmeData() { return nvmeData_; }
  Buffer nvmeFdpStatus(int fd);

  void prepReadUringCmdSqe(struct io_uring_sqe& sqe, int fd, void* buf,
      size_t size, off_t start);
  void prepWriteUringCmdSqe(struct io_uring_sqe& sqe, int fd, void* buf,
      size_t size, off_t start, uint16_t id);
 private:
  void prepFdpUringCmdSqe(struct io_uring_sqe& sqe, int fd, void* buf,
      size_t size, off_t start, uint8_t opcode, uint8_t dtype,
      uint16_t dspec, NvmeData& nvmeData);

  uint16_t getFdpPID(uint16_t fdpPHNDL) {
    // Fetch PID like placementIDs_[placementHandle].
    return placementIDs_[fdpPHNDL];
  }
  NvmeData readNvmeInfo(int fd);
  int nvmeIOMgmtRecv(int fd, uint32_t nsid, void *data, uint32_t data_len,
      uint16_t mos, uint8_t mo);
  void initializeFDP(int fd);
  static constexpr uint16_t kDefaultPIDIdx = 0u;

  std::map<uint16_t, uint16_t> placementIDs_{};
  uint16_t maxPIDIdx_{0};
  uint16_t nextPIDIdx_{0};
  NvmeData nvmeData_{};
};
} // namespace navy
} // namespace cachelib
} // namespace facebook
