#!/usr/bin/env python3
import sys
import hashlib
import binascii
from ecdsa import SigningKey, VerifyingKey, NIST256p

APP_MAX_SIZE = 0x7B00       # 31488 bytes
SIGNATURE_SIZE = 64         # R(32) + S(32)

def read_hex_file(path):
    """Convert Intel HEX to raw binary padded to APP_MAX_SIZE."""
    from intelhex import IntelHex
    ih = IntelHex(path)
    bin_data = ih.tobinarray(start=0, size=APP_MAX_SIZE)
    return bytes(bin_data)

def read_key_file(path):
    """Read hex-encoded key from file and strip whitespace."""
    return open(path, "r").read().strip().replace(" ", "").replace("\n", "")

def pad_firmware(data):
    """Pad firmware to APP_MAX_SIZE with 0xFF."""
    if len(data) > APP_MAX_SIZE:
        raise ValueError(f"Firmware too big! {len(data)} > {APP_MAX_SIZE}")
    return data.ljust(APP_MAX_SIZE, b'\xFF')

def sign_firmware(firmware, private_key_bytes):
    """Sign SHA-256 hash of firmware with private key."""
    sk = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    digest = hashlib.sha256(firmware).digest()
    signature = sk.sign_digest(
        digest,
        sigencode=lambda r, s, order: r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    )
    return signature

def verify_signature(firmware, signature, public_key_bytes):
    """Verify signature against firmware and public key."""
    vk = VerifyingKey.from_string(public_key_bytes, curve=NIST256p)
    digest = hashlib.sha256(firmware).digest()
    r = int.from_bytes(signature[:32], 'big')
    s = int.from_bytes(signature[32:], 'big')
    try:
        return vk.verify_digest(signature, digest, sigdecode=lambda sig, order: (r, s))
    except Exception:
        return False

def create_signed_image(firmware, signature):
    """Create final image with signature at the end."""
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError("Signature must be 64 bytes")
    final_image = bytearray(firmware)
    final_image.extend(signature)
    final_image.extend(b'\xFF' * (256 - SIGNATURE_SIZE))
    return bytes(final_image)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <firmware.hex|bin> <private_key_file.hex> <output.bin> [public_key_file.hex]")
        sys.exit(1)

    fw_path = sys.argv[1]
    priv_key_path = sys.argv[2]
    output_path = sys.argv[3]
    pub_key_path = sys.argv[4] if len(sys.argv) >= 5 else None

    # Read keys
    private_key_hex = read_key_file(priv_key_path)
    private_key_bytes = bytes.fromhex(private_key_hex)

    public_key_bytes = None
    if pub_key_path:
        public_key_hex = read_key_file(pub_key_path)
        public_key_bytes = bytes.fromhex(public_key_hex)

    # Read firmware
    if fw_path.lower().endswith(".hex"):
        try:
            import intelhex
        except ImportError:
            print("Please install intelhex: pip install intelhex")
            sys.exit(1)
        firmware = read_hex_file(fw_path)
    else:
        firmware = open(fw_path, "rb").read()

    firmware = pad_firmware(firmware)

    # Sign
    signature = sign_firmware(firmware, private_key_bytes)

    # Optional verify
    if public_key_bytes:
        if not verify_signature(firmware, signature, public_key_bytes):
            print("[-] Signature verification FAILED. Keys may not match!")
            sys.exit(1)
        print("[+] Signature verification PASSED.")

    # Build output image
    final_image = create_signed_image(firmware, signature)
    with open(output_path, "wb") as f:
        f.write(final_image)

    print(f"[+] Signed firmware written to {output_path}")
    print(f"[+] Firmware size: {len(firmware)} bytes")
    print(f"[+] Signature: {binascii.hexlify(signature).decode()}")
