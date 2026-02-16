#include "ndn/ndn.hpp"

namespace ndn {

namespace {
// Pointer to external Forwarder (set via setForwarder())
// No longer owns an instance to save ~100KB of internal SRAM.
Forwarder* g_forwarderPtr = nullptr;
}  // namespace

void setForwarder(Forwarder& fw) {
    g_forwarderPtr = &fw;
}

Forwarder& getForwarder() {
    return *g_forwarderPtr;
}

Error initialize() {
    // Lightweight init - Forwarder is managed by the application.
    // Call setForwarder() to register the application's Forwarder
    // before using convenience APIs (expressInterest, putData, etc.)
    return Error::Success;
}

}  // namespace ndn
