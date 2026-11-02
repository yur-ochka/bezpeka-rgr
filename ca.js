const crypto = require("crypto");
const fs = require("fs");

// Генерація ключів Root CA
console.log("Генерація ключів Центру Сертифікації (CA)...");
const caKeys = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

fs.writeFileSync("ca_public.pem", caKeys.publicKey);

// Функція підпису сертифіката сервера
function issueCertificate(serverPublicKey, domain = "localhost") {
  const certData = {
    subject: domain,
    issuer: "KPI Root CA",
    validFrom: new Date().toISOString(),
    validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    publicKey: serverPublicKey,
  };

  // Підпис даних сертифіката приватним ключем CA
  const signer = crypto.createSign("SHA256");
  signer.update(JSON.stringify(certData));
  signer.end();
  const signature = signer.sign(caKeys.privateKey, "hex");

  return {
    tbsData: certData,
    signature: signature,
  };
}

module.exports = { issueCertificate };
