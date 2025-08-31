#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_flash.h"
#include "spi_flash_mmap.h"
#include "esp_partition.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_app_format.h"
#include "esp_heap_caps.h"
#include "esp_image_format.h"
#include "bootloader_common.h"
#include "bootloader_flash.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform.h"

#define FIRMWARE_START_ADDR 0x12000 // Start of OTA_0
#define FIRMWARE_MAX_SIZE (1024*1024) // 1MB
#define METADATA_SIZE sizeof(firmware_metadata_t)

static const char *TAG = "secure_boot";

// simulated public key
const char *ecdsa_public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";

typedef struct {
    uint8_t version;
    uint8_t hash[32]; // SHA256
    uint8_t signature[64]; // ECDSA
    uint8_t signature_algo;
    uint8_t firmware_version;
} __attribute__((packed)) firmware_metadata_t;

bool verify_firmware_signature(const uint8_t *firmware, size_t firmware_len, firmware_metadata_t *meta) {
    int ret;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_parse_public_key(&pk, (const uint8_t *)ecdsa_public_key_pem, strlen(ecdsa_public_key_pem) + 1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to parse public key");
        return false;
    }
    // Verify the signature
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, meta->hash, 0, meta->signature, 64);
    mbedtls_pk_free(&pk);
    if (ret != 0) {
        ESP_LOGE(TAG, "Signature verification failed");
        return false;
    }
    ESP_LOGI(TAG, "Firmware signature verified");
    return true;
}

bool verify_firmware_hash(const uint8_t *firmware, size_t firmware_len, const uint8_t *expected_hash) {
    uint8_t actual_hash[32];
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, firmware, firmware_len);
    mbedtls_sha256_finish(&sha, actual_hash);
    mbedtls_sha256_free(&sha);

    if (memcmp(actual_hash, expected_hash, 32) != 0) {
        ESP_LOGE(TAG, "Hash mismatch: firmware may be tampered");
        return false;
    }
    ESP_LOGI(TAG, "Firmware hash verified");
    return true;
}

void app_main(void) {
    ESP_LOGI(TAG, "Starting secure bootloader");
    // Read firmware and metadata from flash
    uint8_t *firmware = heap_caps_malloc(FIRMWARE_MAX_SIZE, MALLOC_CAP_8BIT);
    if (!firmware) {
        ESP_LOGE(TAG, "Failed to allocate memory for firmware");
        esp_restart();
    }
    esp_err_t err = esp_flash_read(NULL, firmware, FIRMWARE_START_ADDR, FIRMWARE_MAX_SIZE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_flash_read failed: %s", esp_err_to_name(err));
        esp_restart();
    }
    firmware_metadata_t *meta = (firmware_metadata_t *)(firmware + FIRMWARE_MAX_SIZE - METADATA_SIZE);
    size_t firmware_len = FIRMWARE_MAX_SIZE - METADATA_SIZE;
    if (!verify_firmware_hash(firmware, firmware_len, meta->hash)) {
        ESP_LOGE(TAG, "Firmware hash verification failed");
        esp_restart();
    }
    if (!verify_firmware_signature(firmware, firmware_len, meta)) {
        ESP_LOGE(TAG, "Firmware signature verification failed");
        esp_restart();
    }
    // Check rollback
    uint32_t current_version = meta->firmware_version;
    uint32_t stored_version = 3; // simulate NVS read
    if (current_version < stored_version) {
        ESP_LOGE(TAG, "Firmware rollback detected");
        esp_restart();
    }
    ESP_LOGI(TAG, "Booting verified firmware");
    // Jump to application
    esp_image_metadata_t image_data;

    // Define the app partition manually
    esp_partition_pos_t app_partition = {
        .offset = FIRMWARE_START_ADDR,
        .size = FIRMWARE_MAX_SIZE
    };
    err = esp_image_verify(ESP_IMAGE_VERIFY, &app_partition, &image_data);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Firmware image verification failed: %s", esp_err_to_name(err));
        esp_restart();
    }
}