const net = require("net");
const crypto = require("crypto");
const fs = require("fs");

const HOST = "127.0.0.1";
const PORT = 8080;

// Завантаження публічного ключа Центру Сертифікації
const caPublicKey = fs.readFileSync("ca_public.pem", "utf8");

function encryptAES(key, text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");
  return { iv: iv.toString("hex"), ciphertext: encrypted, tag };
}

function decryptAES(key, data) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(data.iv, "hex"),
  );
  decipher.setAuthTag(Buffer.from(data.tag, "hex"));
  let decrypted = decipher.update(data.ciphertext, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// Перевірка сертифіката у CA
function verifyCertificate(cert, caPubKey) {
  const verifier = crypto.createVerify("SHA256");
  verifier.update(JSON.stringify(cert.tbsData));
  verifier.end();

  const isValidSignature = verifier.verify(caPubKey, cert.signature, "hex");
  const isNotExpired = new Date() < new Date(cert.tbsData.validTo);

  return isValidSignature && isNotExpired;
}

const socket = net.connect(PORT, HOST, () => {
  console.log("Підключено до сервера.");

  // Ініціювання (ClientHello)
  const clientRandom = crypto.randomBytes(32);
  socket.write(
    JSON.stringify({
      type: "ClientHello",
      clientRandom: clientRandom.toString("hex"),
    }) + "\n",
  );
  console.log("1. Відправлено ClientHello");

  let state = "WAIT_SERVER_HELLO";
  let serverRandom = null;
  let serverPublicKey = null;
  let premasterSecret = null;
  let sessionKey = null;
  let buffer = "";

  socket.on("data", (chunk) => {
    buffer += chunk.toString();
    let lines = buffer.split("\n");
    buffer = lines.pop();

    for (let line of lines) {
      if (!line.trim()) continue;
      const msg = JSON.parse(line);

      if (state === "WAIT_SERVER_HELLO" && msg.type === "ServerHello") {
        //  Отримання ServerHello та сертифіката
        serverRandom = Buffer.from(msg.serverRandom, "hex");
        const cert = msg.certificate;
        console.log("2. Отримано ServerHello та сертифікат");

        // Автентифікація через Центр Сертифікації
        console.log("3. Перевірка сертифіката в CA...");
        const isCertValid = verifyCertificate(cert, caPublicKey);

        if (!isCertValid) {
          console.error(
            "Помилка: Сертифікат сервера недійсний або підроблений!",
          );
          socket.end();
          return;
        }
        console.log(
          "3. Автентифікація успішна: Сертифікат дійсний через Root CA.",
        );

        serverPublicKey = cert.tbsData.publicKey;

        //  Обмін секретом premaster
        premasterSecret = crypto.randomBytes(48);
        const encryptedPremaster = crypto.publicEncrypt(
          {
            key: serverPublicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
          },
          premasterSecret,
        );

        socket.write(
          JSON.stringify({
            type: "Premaster",
            encryptedPremaster: encryptedPremaster.toString("hex"),
          }) + "\n",
        );
        console.log("4. Згенеровано та відправлено зашифрований premaster");

        //  Генерація ключів сеансу
        sessionKey = crypto
          .createHmac("sha256", premasterSecret)
          .update(Buffer.concat([clientRandom, serverRandom]))
          .digest();
        console.log("5. Згенеровано сесійний ключ");

        // Готовність клієнта (Finished)
        const clientFinishedPayload = encryptAES(
          sessionKey,
          "CLIENT_FINISHED_OK",
        );
        socket.write(
          JSON.stringify({
            type: "ClientFinished",
            payload: clientFinishedPayload,
          }) + "\n",
        );

        state = "WAIT_SERVER_FINISHED";
      } else if (
        state === "WAIT_SERVER_FINISHED" &&
        msg.type === "ServerFinished"
      ) {
        //  Перевірка готовності сервера
        const serverFinishedText = decryptAES(sessionKey, msg.payload);
        if (serverFinishedText !== "SERVER_FINISHED_OK") {
          console.error("Помилка статусу сервера");
          socket.end();
          return;
        }
        console.log("6. Отримано підтвердження сервера");
        console.log("7. Рукостискання завершено.\n");

        // Захищена передача даних
        const secretPayload =
          "Секретні дані текстового файлу, передані по TLS каналу.";
        console.log(`Надсилання даних: "${secretPayload}"`);

        const encryptedPayload = encryptAES(sessionKey, secretPayload);
        socket.write(
          JSON.stringify({
            type: "AppData",
            payload: encryptedPayload,
          }) + "\n",
        );

        state = "SECURE_CHANNEL";
      } else if (state === "SECURE_CHANNEL" && msg.type === "AppData") {
        const responseText = decryptAES(sessionKey, msg.payload);
        console.log(`Відповідь сервера: "${responseText}"`);
        socket.end();
      }
    }
  });
});
