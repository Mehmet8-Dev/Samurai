#include "curve.hpp"

#include <zmq.h>

namespace samurai::control {

CurveKeypair GenerateCurveKeypair() {
  CurveKeypair kp;
  char public_key[41] = {0};
  char secret_key[41] = {0};
  if (zmq_curve_keypair(public_key, secret_key) == 0) {
    kp.public_key = public_key;
    kp.secret_key = secret_key;
    kp.ok = true;
  }
  return kp;
}

}  // namespace samurai::control
