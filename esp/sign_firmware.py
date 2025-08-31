import argparse
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.backends import default_backend

def load_private_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    
def sign_firmware(firmware_path, key_path, out_path, use_rsa):
    # Read firmware
    with open(firmware_path, "rb") as f:
        firmware = f.read()
    # Hash firmware
    digest = hashlib.sha256(firmware).digest()
    # Load key
    private_key = load_private_key(key_path)
    # Sign hash
    if use_rsa:
        signature = private_key.sign(digest, padding.PKCS1v15(), hashes.SHA256())
    else:
        signature = private_key.sign(digest, ec.ECDSA(hashes.SHA256()))
    # Output: firmware + signature
    with open(out_path, "wb") as f:
        f.write(firmware)
        f.write(signature)
    print("Firmware signed and saved to: {out_path}")
    print("Signature size: {len(signature)} bytes")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sign ESP32 firmware with RSA or ECDSA")
    parser.add_argument("--key", required=True, help="Path to private.pem")
    parser.add_argument("--in", dest="firmware_path", required=True, help="Input firmware binary")
    parser.add_argument("--out", dest="out_path", required=True, help="Output signed firmware")
    parser.add_argument("--rsa", action="store_true", help="Use RSA instead of ECDSA")
    args = parser.parse_args()
    sign_firmware(args.firmware_path, args.key, args.out_path, args.rsa)