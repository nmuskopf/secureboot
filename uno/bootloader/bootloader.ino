#include <avr/io.h>
#include <avr/pgmspace.h>
#include <avr/boot.h>
#include <util/delay.h>
#include <CustomJWT.h>
#include <uECC.h>

#define APP_START_ADDR 0x0000
#define SIGNATURE_ADDR 0x7B00 // last 256B before bootloader
#define APP_MAX_SIZE   0x7B00 // App must be smaller than this

uint8_t firmware_hash[32];
uint8_t signature[64];
const uint8_t public_key[] = {""}; // Paste your public key here!

void read_flash(uint16_t addr, uint8_t *buf, uint16_t len) {
  for (uint16_t i = 0; i < len; i++) {
    buf[i] = pgm_read_byte_near(addr + i);
  }
}

void compute_firmware_hash() {
  uint8_t full_firmware[APP_MAX_SIZE];
  read_flash(APP_START_ADDR, full_firmware, APP_MAX_SIZE);
  CustomJWT jwt(full_firmware, APP_MAX_SIZE, firmware_hash);
}

void load_signature() {
  read_flash(SIGNATURE_ADDR, signature, sizeof(signature));
}

int verify_signature() {
  return uECC_verify(public_key, firmware_hash, sizeof(firmware_hash), signature, uECC_secp256r1());
}

void jump_to_application() {
  void (*app_start)(void) = (void (*)(void))APP_START_ADDR;
  app_start();
}

int main(void) {
  compute_firmware_hash();
  load_signature();
  if (verify_signature()) {
    jump_to_application();
  } else {
    DDRB |= (1 << PB5); // Error indication: blink LED
    while (1) {
      PORTB ^= (1 << PB5);
      _delay_ms(200);
    }
  }
  return 0;
}