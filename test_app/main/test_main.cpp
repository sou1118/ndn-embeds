#include "esp_log.h"
#include "unity.h"
#include <stdio.h>

// NDN test runner function prototypes
extern void run_tlv_tests(void);
extern void run_name_tests(void);
extern void run_interest_tests(void);
extern void run_data_tests(void);
extern void run_signature_tests(void);
extern void run_link_tests(void);
extern void run_certificate_tests(void);
extern void run_pit_tests(void);
extern void run_cs_tests(void);
extern void run_fib_tests(void);
extern void run_forwarder_tests(void);
extern void run_espnow_face_tests(void);

static const char* TAG = "NDN_TEST";

extern "C" void app_main(void) {
    ESP_LOGI(TAG, "Starting NDN unit tests...");

    UNITY_BEGIN();

    ESP_LOGI(TAG, "=== TLV Tests ===");
    run_tlv_tests();

    ESP_LOGI(TAG, "=== Name Tests ===");
    run_name_tests();

    ESP_LOGI(TAG, "=== Interest Tests ===");
    run_interest_tests();

    ESP_LOGI(TAG, "=== Data Tests ===");
    run_data_tests();

    ESP_LOGI(TAG, "=== Signature Tests ===");
    run_signature_tests();

    ESP_LOGI(TAG, "=== Link Tests ===");
    run_link_tests();

    ESP_LOGI(TAG, "=== Certificate Tests ===");
    run_certificate_tests();

    ESP_LOGI(TAG, "=== PIT Tests ===");
    run_pit_tests();

    ESP_LOGI(TAG, "=== CS Tests ===");
    run_cs_tests();

    ESP_LOGI(TAG, "=== FIB Tests ===");
    run_fib_tests();

    ESP_LOGI(TAG, "=== Forwarder Tests ===");
    run_forwarder_tests();

    ESP_LOGI(TAG, "=== ESP-NOW Face Tests ===");
    run_espnow_face_tests();

    UNITY_END();

    ESP_LOGI(TAG, "Test run complete.");
}
