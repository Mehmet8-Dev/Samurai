#include "anti_tamper.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <link.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/sha.h>

namespace samurai::licensing {

namespace {

std::string BytesToHex(const unsigned char* data, size_t len) {
  std::ostringstream oss;
  for (size_t i = 0; i < len; ++i) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
  }
  return oss.str();
}

struct PhdrContext {
  uintptr_t mem_start = 0;
  size_t mem_size = 0;
  off_t file_offset = 0;
  size_t file_size = 0;
  bool found = false;
};

int PhdrCallback(dl_phdr_info* info, size_t /*size*/, void* data) {
  auto* ctx = static_cast<PhdrContext*>(data);
  // Main executable has empty name or matches the binary
  if (info->dlpi_name && info->dlpi_name[0] != '\0') {
    return 0;
  }
  for (int i = 0; i < info->dlpi_phnum; ++i) {
    const ElfW(Phdr)& ph = info->dlpi_phdr[i];
    if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) {
      ctx->mem_start = info->dlpi_addr + ph.p_vaddr;
      ctx->mem_size = ph.p_memsz;
      ctx->file_offset = static_cast<off_t>(ph.p_offset);
      ctx->file_size = ph.p_filesz;
      ctx->found = true;
      return 1;  // Stop at the first executable segment of the main binary
    }
  }
  return 0;
}

}  // namespace

bool IsDebuggerAttached() {
  // Check /proc/self/status for TracerPid (reliable, non-destructive detection of gdb/lldb/strace)
  std::ifstream status_file("/proc/self/status");
  if (status_file) {
    std::string line;
    while (std::getline(status_file, line)) {
      if (line.rfind("TracerPid:", 0) == 0) {
        std::istringstream iss(line.substr(10));
        long tracer_pid = 0;
        if (iss >> tracer_pid && tracer_pid > 0) {
          return true;
        }
        break;
      }
    }
  }

  // Check /proc/self/wchan for ptrace_stop
  std::ifstream wchan_file("/proc/self/wchan");
  if (wchan_file) {
    std::string wchan;
    if (std::getline(wchan_file, wchan)) {
      if (wchan.find("ptrace_stop") != std::string::npos) {
        return true;
      }
    }
  }

  return false;
}

IntegrityResult VerifySelfIntegrity() {
  IntegrityResult res;

  if (IsDebuggerAttached()) {
    res.ok = false;
    res.reason = "Debugger or tracer detected (TracerPid != 0 / ptrace restricted)";
    return res;
  }

  PhdrContext ctx;
  dl_iterate_phdr(PhdrCallback, &ctx);

  if (!ctx.found || ctx.mem_start == 0 || ctx.file_size == 0) {
    // If phdr was not found (e.g. non-standard static link), fail closed in release
    res.ok = false;
    res.reason = "Executable code segment info unavailable for comparison";
    return res;
  }

  // Calculate SHA-256 of the in-memory executable segment
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(ctx.mem_start), ctx.file_size, hash);
  res.text_sha256 = BytesToHex(hash, SHA256_DIGEST_LENGTH);

  // Compare memory pages with on-disk executable (fail closed if inaccessible or tampered)
  int fd = ::open("/proc/self/exe", O_RDONLY);
  if (fd < 0) {
    res.ok = false;
    res.reason = "Cannot access /proc/self/exe for self-integrity check";
    return res;
  }

  if (::lseek(fd, ctx.file_offset, SEEK_SET) != ctx.file_offset) {
    ::close(fd);
    res.ok = false;
    res.reason = "Failed to seek to executable code segment in /proc/self/exe";
    return res;
  }

  std::vector<uint8_t> disk_buf(65536);
  size_t remaining = ctx.file_size;
  size_t offset_in_seg = 0;

  while (remaining > 0) {
    size_t to_read = std::min(remaining, disk_buf.size());
    ssize_t n = ::read(fd, disk_buf.data(), to_read);
    if (n <= 0) {
      ::close(fd);
      res.ok = false;
      res.reason = "Unexpected EOF or read error from /proc/self/exe";
      return res;
    }

    const uint8_t* mem_ptr = reinterpret_cast<const uint8_t*>(ctx.mem_start + offset_in_seg);
    if (std::memcmp(mem_ptr, disk_buf.data(), static_cast<size_t>(n)) != 0) {
      ::close(fd);
      res.ok = false;
      res.reason = "Code patch / memory modification detected in executable segment";
      return res;
    }

    remaining -= static_cast<size_t>(n);
    offset_in_seg += static_cast<size_t>(n);
  }
  ::close(fd);

  res.ok = true;
  return res;
}

}  // namespace samurai::licensing
