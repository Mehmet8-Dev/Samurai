#include "../include/oracle.hpp"

#include <string>
#include <vector>

namespace py = pybind11;

namespace ddos_samurai::gpu_cuda_payload {

py::dict evaluate_oracle(
    const py::dict& plan_batch,
    const py::dict& run_result,
    const py::dict& checks) {
  (void)plan_batch;
  const int sent = run_result.contains(py::str("sent")) ? py::cast<int>(run_result[py::str("sent")]) : 0;
  const int errors = run_result.contains(py::str("errors")) ? py::cast<int>(run_result[py::str("errors")]) : 0;
  const bool require_strict = checks.contains(py::str("require_strict")) ? py::cast<bool>(checks[py::str("require_strict")]) : true;
  const bool strict_ok =
      !require_strict ||
      (run_result.contains(py::str("stateful_runtime_strict")) &&
       py::cast<int>(run_result[py::str("stateful_runtime_strict")]) != 0);

  py::list reasons;
  if (sent <= 0) {
    reasons.append(py::str("no_sent_traffic"));
  }
  if (errors > sent + 1) {
    reasons.append(py::str("error_ratio_high"));
  }
  if (!strict_ok) {
    reasons.append(py::str("strict_runtime_not_enforced"));
  }

  py::dict out;
  out["pass"] = py::bool_(py::len(reasons) == 0);
  out["reasons"] = reasons;
  out["sent"] = py::int_(sent);
  out["errors"] = py::int_(errors);
  return out;
}

}  // namespace ddos_samurai::gpu_cuda_payload

