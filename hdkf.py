#!/usr/bin/env python3
"""
Desencriptador ECDH‑AES‑GCM
--------------------------------------

Requisitos:
    pip install cryptography
"""

import base64
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BANNER = r"""
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣤⣤⣤⣤⣄⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⠶⣻⠝⠋⠠⠔⠛⠁⡀⠀⠈⢉⡙⠓⠶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⢋⣴⡮⠓⠋⠀⠀⢄⠀⠀⠉⠢⣄⠀⠈⠁⠀⡀⠙⢶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⢁⣔⠟⠁⠀⠀⠀⠀⠀⠈⡆⠀⠀⠀⠈⢦⡀⠀⠀⠘⢯⢢⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⠃⠀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠸⠀⠀⠀⠀⠀⢳⣦⡀⠀⠀⢯⠀⠈⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠆⡄⢠⢧⠀⣸⠀⠀⠀⠀⠀⠀⠀⢰⠀⣄⠀⠀⠀⠀⢳⡈⢶⡦⣿⣷⣿⢉⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣯⣿⣁⡟⠈⠣⡇⠀⠀⢸⠀⠀⠀⠀⢸⡄⠘⡄⠀⠀⠀⠈⢿⢾⣿⣾⢾⠙⠻⣾⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡿⣮⠇⢙⠷⢄⣸⡗⡆⠀⢘⠀⠀⠀⠀⢸⠧⠀⢣⠀⠀⠀⡀⡸⣿⣿⠘⡎⢆⠈⢳⣽⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⢻⢷⣄⠀⠀⠀⠀⠀⠀⣾⣳⡿⡸⢀⣿⠀⠀⢸⠙⠁⠀⠼⠀⠀⠀⠀⢸⣇⠠⡼⡤⠴⢋⣽⣱⢿⣧⠀⢳⠈⢧⠀⢻⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⡿⣠⡣⠃⣿⠃⠀⠀⠀⠀⣸⣳⣿⠇⣇⢸⣿⢸⣠⠼⠀⠀⠀⡇⠀⡀⠉⠒⣾⢾⣆⢟⣳⡶⠓⠶⠿⢼⣿⣇⠈⡇⠘⢆⠈⢿⡘⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⢷⣍⣤⡶⣿⡄⠀⠀⠀⢠⣿⠃⣿⠀⡏⢸⣿⣿⠀⢸⠀⠀⢠⡗⢀⠇⠀⢠⡟⠀⠻⣾⣿⠀⠀⠀⠀⡏⣿⣿⡀⢹⡀⠈⢦⠈⢷⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢁⣤⣄⠁⠀⠀⠀⣼⡏⢰⣟⠀⣇⠘⣿⣿⣾⣾⣆⢀⣾⠃⣼⢠⣶⣿⣭⣷⣶⣾⣿⣤⠀⠀⠀⡇⡯⣍⣧⠀⣷⠄⠈⢳⡀⢻⡁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠺⣿⡿⠀⠀⠀⠀⡿⢀⣾⣧⠀⡗⡄⢿⣿⡙⣽⣿⣟⠛⠚⠛⠙⠉⢹⣿⣿⣦⠀⢸⡿⠀⠀⠀⢰⡯⣌⢻⡀⢸⢠⢰⡄⠹⡷⣿⣦⣤⠤⣶⡇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⣇⣾⣿⢸⢠⣧⢧⠘⣿⡇⠸⣿⢿⡆⠀⠀⠀⠀⠘⣯⠇⣿⠂⣸⢰⠀⠀⢀⣸⡧⣊⣼⡇⢸⣼⣸⣷⢣⢻⣄⠉⠙⠛⠉⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣳⣤⣴⣿⣏⣿⣾⢸⣿⡘⣧⣘⢿⣀⡙⣞⠁⠀⠀⠀⠀⢀⡬⢀⣉⢠⣧⡏⠀⠀⡎⣿⣿⣿⣿⠃⣸⡏⣿⣿⡎⢿⡘⡆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⣠⣼⣿⣿⣿⣼⣿⣧⢿⣿⣿⣯⡻⠟⠀⠀⠀⠀⠀⠐⢯⠣⡽⢟⣽⠀⠀⢘⡇⣿⣿⣿⡟⣴⣿⣷⣿⣿⣧⣿⣷⡽⠀⠀⠀⠀⠀⠀⠀
⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣼⣹⣿⣇⣸⣿⣿⣿⣻⣚⣿⡿⣿⣿⣦⣤⣀⡉⠃⠀⢀⣀⣤⡶⠛⡏⠀⢀⣼⢸⣿⣿⣿⣿⣿⣿⣿⢋⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀
⣿⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠒⠒⠒⢭⢻⣽⣿⣿⣿⣿⣿⣿⢿⠿⣿⡏⠀⡼⠁⣀⣾⣿⣿⣿⣿⡿⣿⣿⣟⡻⣿⣿⡿⠣⠟⠀⠀⠀⠀⠀⠀⠀⠀
⠸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢧⢿⣯⡽⠿⠛⠋⣵⢟⣋⣿⣶⣞⣤⣾⣿⣿⡟⢉⡿⢋⠻⢯⡉⢻⡟⢿⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡞⣿⣆⡀⠀⡼⡏⠉⠚⠭⢉⣠⠬⠛⠛⢁⡴⣫⠖⠁⠀⠀⣩⠟⠁⣸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠈⢷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣽⣿⣿⣾⠳⡙⣦⡤⠜⠊⠁⠀⣀⡴⠯⠾⠗⠒⠒⠛⠛⠛⠛⠛⠓⠿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⣻⣿⣿⠔⢪⠓⠬⢍⠉⣩⣽⢻⣤⣶⣦⠀⠀⠀⢀⣀⣤⣴⣾⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠹⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣾⡏⢦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣯⣿⣿⠀⠀⣇⠀⣠⠎⠁⢹⡎⡟⡏⣷⣶⠿⠛⡟⠛⠛⣫⠟⠉⢿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢻⡄⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣷⠈⢷⡤⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣾⣷⡀⣀⣀⣷⡅⠀⠀⠈⣷⢳⡇⣿⠀⠀⣸⠁⢠⡾⣟⣛⣻⣟⡿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢯⢻⣏⡵⠿⠿⢤⣄⠀⢀⣿⢸⣹⣿⣀⣴⣿⣴⣿⣛⠋⠉⠉⡉⠛⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡎⣿⣥⣶⠖⢉⣿⡿⣿⣿⡿⣿⣟⠿⠿⣿⣿⣿⡯⠻⣿⣿⣿⣷⡽⣿⡗⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡘⣿⣩⠶⣛⣋⡽⠿⣷⢬⣙⣻⣿⣿⣿⣯⣛⠳⣤⣬⡻⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀
⠀⣿⣛⣻⣿⡿⠿⠟⠗⠶⠶⠶⠶⠤⠤⢤⠤⡤⢤⣤⣤⣤⣤⣄⣀⣀⣀⣀⣀⣀⣀⣀⣣⢹⣷⣶⣿⣿⣦⣴⣟⣛⣯⣤⣿⣿⣿⣿⣿⣷⣌⣿⣿⣿⣿⣿⣿⣿⣤⣤⣤⣤⣤⣤⣄
⠀⠉⠙⠛⠛⠛⠛⠛⠻⠿⠿⠿⠷⠶⠶⢶⣶⣶⣶⣶⣤⣤⣤⣤⣤⣥⣬⣭⣭⣉⣩⣍⣙⣏⣉⣏⣽⣶⣶⣶⣤⣤⣬⣤⣤⣾⣿⠶⠾⠿⠿⠿⠿⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠃
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠛⠛⠛⠛⠛⠛⠋⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

"""


def b64in(prompt: str) -> bytes:
    """Lee una cadena Base64 (sin espacios) y la decodifica."""
    raw = input(prompt).strip()
    return base64.b64decode(raw)


def try_decrypt(aes_key: bytes, iv: bytes, ct: bytes, aad: bytes | None = None):
    """Intenta descifrar con AES‑GCM; devuelve plaintext o None."""
    try:
        return AESGCM(aes_key).decrypt(iv, ct, aad)
    except Exception:
        return None


def main() -> None:
    print(BANNER)

    # ── 1. Entrada ────────────────────────────────────────────────
    priv_der = b64in("🔐 Clave privada del cliente (Base64 DER PKCS8):\n")
    pub_server = b64in("\n🔑 Clave pública del servidor (Base64 X9.62):\n")
    iv = b64in("\n🧊 IV (Base64, 12 bytes decodificados):\n")
    ct = b64in("\n📦 encryptedData (Base64):\n")

    # Opcional: salt y/o info personalizados
    salt_in = input("\n¿Salt HKDF en Base64? (enter para ninguno):\n").strip()
    salt_custom = base64.b64decode(salt_in) if salt_in else None

    info_in = (
        input(
            "ℹ  ¿info HKDF en texto? (enter para usar la lista por defecto):\n"
        ).encode()
        or None
    )

    # ── 2. Carga de claves y shared‑secret ─────────────────────────
    client_priv = serialization.load_der_private_key(priv_der, password=None)
    server_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), pub_server
    )
    shared = client_priv.exchange(ec.ECDH(), server_pub)
    print(f"\n🔑 Shared‑secret (hex): {shared.hex()}")

    # ── 3. Estrategias de derivación ───────────────────────────────
    strategies: list[tuple[str, bytes]] = []

    # 3‑A) Clave “en crudo”
    if len(shared) == 32:
        strategies.append(("raw_shared_secret", shared))
    else:  # por si saliera de otra curva → llevamos a 32 bytes con SHA‑256
        strategies.append(
            ("sha256(shared_secret)", hashes.Hash(hashes.SHA256()).finalize())
        )

    # 3‑B) HKDF sin salt, varias info
    default_infos = [
        b"",
        b"deckey",
        b"ecdh",
        b"shared-secret",
        b"auth-deckey",
        b"gse-biometrix",
    ]
    for info in default_infos if info_in is None else [info_in]:
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        ).derive(shared)
        strategies.append((f"HKDF‑nosalt info={info!r}", key))

    # 3‑C) HKDF con salt (si lo dieron)
    if salt_custom is not None:
        info = info_in or b"custom-info"
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_custom,
            info=info,
        ).derive(shared)
        strategies.append((f"HKDF salt={salt_in or '…'} info={info!r}", key))

    # ── 4. Prueba de descifrado ────────────────────────────────────
    ok = False
    for label, key in strategies:
        pt = try_decrypt(key, iv, ct)
        if pt is not None:
            print(f"\n✅  ¡Descifrado con: {label}!")
            print("────────────────────────────────────────────────────")
            try:
                print(pt.decode("utf-8"))
            except UnicodeDecodeError:
                print(pt)  # binario
            print("\n────────────────────────────────────────────────────")
            ok = True
            break
        else:
            print(f"❌  Falló con {label}")

    if not ok:
        print("\n[!]Ninguna estrategia funcionó. Prueba con otro salt/info/AAD.")

    # ── 5. Guarda log ─────────────────────────────────────────────
    out = Path(f"auditoria_{datetime.now():%Y%m%d_%H%M%S}.txt")
    out.write_text(
        f"shared_secret = {shared.hex()}\n"
        + "\n".join(f"{lbl}: {k.hex()}" for lbl, k in strategies)
    )
    print(f"\n📝 Informe minimal guardado en {out}")


if __name__ == "__main__":
    main()
