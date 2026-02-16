#include "ndn/ndn.hpp"

namespace ndn {

namespace {
// Global Forwarder instance
Forwarder g_forwarder;
}  // namespace

Forwarder& getForwarder() {
    return g_forwarder;
}

Error initialize() {
    return g_forwarder.init();
}

}  // namespace ndn
