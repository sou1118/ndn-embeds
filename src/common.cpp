#include "ndn/common.hpp"
#include "esp_random.h"
#include "esp_timer.h"

namespace ndn {

TimeMs currentTimeMs() {
    return static_cast<TimeMs>(esp_timer_get_time() / 1000);
}

uint32_t generateRandomNonce() {
    return esp_random();
}

}  // namespace ndn
