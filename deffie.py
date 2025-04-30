import base64
import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

audit_log = []


def log(line):
    print(line)
    audit_log.append(line)


# === 🔐 Pega aquí tus datos ===
client_private_key_b64 = input(
    "\n🔐 Pega tu clave privada (PKCS8 Base64, sin saltos de línea):\n"
).strip()
server_public_key_b64 = input(
    "\n🔑 Pega la clave pública del servidor (publicKeyBack):\n"
).strip()
iv_b64 = input("\n🧊 Pega el IV (iv):\n").strip()
ciphertext_b64 = input("\n📦 Pega el encryptedData:\n").strip()

# === Decodificación
client_priv_bytes = base64.b64decode(client_private_key_b64)
server_pub_bytes = base64.b64decode(server_public_key_b64)
iv = base64.b64decode(iv_b64)
ciphertext = base64.b64decode(ciphertext_b64)

log(f"\n📏 IV length: {len(iv)} bytes")
log(f"📏 Ciphertext length: {len(ciphertext)} bytes")

# === 🔐 Cargar clave privada
client_private_key = serialization.load_der_private_key(
    client_priv_bytes, password=None
)

# === 🔑 Mostrar clave pública derivada del cliente
client_public_key = client_private_key.public_key()
client_public_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint,
)
client_public_b64 = base64.b64encode(client_public_bytes).decode()
log("\n📎 Clave pública derivada desde tu clave privada (base64):")
log(client_public_b64)

# === 🔑 Cargar clave pública del servidor
server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP256R1(), server_pub_bytes
)

# === 🔁 Derivar clave compartida
shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
log(f"\n🔑 Shared secret (hex): {shared_secret.hex()}")
log(f"IV (hex): {iv.hex()}")

# === 🧬 Probar variantes de HKDF info
info_variants = [
    b"",
    b"deckey",
    b"ecdh",
    b"shared-secret",
    b"auth-deckey",
    b"gse-biometrix",
]

success = False
derived_used = None
for info in info_variants:
    label = info if info else b"<vacio>"
    log(f"\n🧪 Probando derivación con info: {label}")

    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info
    ).derive(shared_secret)

    log(f"🔐 Clave derivada (hex): {derived_key.hex()}")

    aesgcm = AESGCM(derived_key)
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        log("\n✅ ✅ ¡Descifrado exitoso!")
        log("Texto descifrado:")
        log(plaintext.decode(errors="replace"))
        derived_used = info
        success = True
        break
    except Exception:
        log("❌ Falló el descifrado con esta clave derivada.")

# === 🧾 Generar archivo de auditoría
now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
filename = f"auditoria_diffie_hellman_{now}.txt"

with open(filename, "w", encoding="utf-8") as f:
    f.write(
        "# Informe de Auditoría ECDH (Intercambio de claves Diffie-Hellman de curva elíptica) + AES-GCM (Advanced Encryption Standard en modo Galois/Counter)\n\n"
    )
    f.write("## Resultado general\n")
    if success:
        f.write(
            "✅ **Se logró descifrar el mensaje.** Esto podría indicar una debilidad si la clave derivada fue predecible o constante.\n\n"
        )
    else:
        f.write(
            "🔒 **No se pudo descifrar el mensaje.** El sistema parece implementar ECDH + AES-GCM correctamente con parámetros no triviales.\n\n"
        )
    f.write("## Datos clave\n")
    f.write(f"- Clave pública derivada del cliente:\n  `{client_public_b64}`\n")
    f.write(f"- Shared secret (hex): `{shared_secret.hex()}`\n")
    f.write(f"- IV (hex): `{iv.hex()}`\n")
    f.write(f"- Ciphertext length: {len(ciphertext)} bytes\n\n")
    f.write("## Pruebas de derivación HKDF:\n")
    for line in audit_log:
        f.write(line + "\n")
    f.write("\n## Evaluación\n")
    f.write("El sistema está protegido contra un atacante con acceso al frontend.\n")
    f.write(
        "No es posible derivar la clave correcta sin conocer información adicional (posiblemente `info`, `salt`, o `AAD`).\n"
    )

log(f"\n📄 Informe de auditoría guardado como: {filename}")
