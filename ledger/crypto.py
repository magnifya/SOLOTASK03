"""签名与验签：基于 cryptography 的 Ed25519。

交易签名报文为 models.canonical_message，公钥与签名均以小写
十六进制字符串传输。另提供 generate_keypair / sign 供 CLI 与测试使用。
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .models import canonical_message

_RAW_PRIVATE = serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
_RAW_PUBLIC = serialization.Encoding.Raw, serialization.PublicFormat.Raw


def generate_keypair() -> tuple[str, str]:
    """返回 (私钥十六进制, 公钥十六进制)。"""
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(*_RAW_PRIVATE).hex()
    pub_hex = priv.public_key().public_bytes(*_RAW_PUBLIC).hex()
    return priv_hex, pub_hex


def sign(private_key_hex: str, message: bytes) -> str:
    """用十六进制私钥对报文签名，返回十六进制签名。"""
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return priv.sign(message).hex()


def verify_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """校验签名是否合法；任何解析/验签错误都视为不合法。"""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), message)
        return True
    except (ValueError, InvalidSignature, TypeError):
        return False
