(async () => {
  const originalGenerateKey = crypto.subtle.generateKey;

  crypto.subtle.generateKey = async function (algo, extractable, keyUsages) {
    const keyPair = await originalGenerateKey.call(this, algo, extractable, keyUsages);

    // Exportar clave privada en PKCS8 (formato compatible con Python)
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const pkcs8B64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8)));

    console.log("--> Clave privada exportada (PKCS8 Base64):", pkcs8B64);

    return keyPair;
  };
})();
