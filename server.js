const net = require("net");
const crypto = require("crypto");
const { issueCertificate } = require("./ca");

const PORT = 8080;

// Генерація RSA ключів сервера
console.log("Генерація RSA ключів сервера...");
const { publicKey: serverPublicKey, privateKey: serverPrivateKey } =
  crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

// Отримання підписаного сертифіката від CA
const serverCertificate = issueCertificate(serverPublicKey, "localhost");
console.log("Сертифікат сервера успішно підписано CA.");

// Симетричне шифрування AES-256-GCM
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

const server = net.createServer((socket) => {
  console.log("\nКлієнт підключився.");

  let state = "WAIT_CLIENT_HELLO";
  let clientRandom = null;
  let serverRandom = null;
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

      if (state === "WAIT_CLIENT_HELLO" && msg.type === "ClientHello") {
        //  Отримання ClientHello
        clientRandom = Buffer.from(msg.clientRandom, "hex");
        console.log("1. Отримано ClientHello");

        // Відповідь ServerHello + X.509 Сертифікат
        serverRandom = crypto.randomBytes(32);
        const serverHello = {
          type: "ServerHello",
          serverRandom: serverRandom.toString("hex"),
          certificate: serverCertificate,
        };
        socket.write(JSON.stringify(serverHello) + "\n");
        console.log("2. Відправлено ServerHello та SSL-сертифікат");

        state = "WAIT_PREMASTER";
      } else if (state === "WAIT_PREMASTER" && msg.type === "Premaster") {
        //  Розшифрування premaster
        const encryptedBuf = Buffer.from(msg.encryptedPremaster, "hex");
        premasterSecret = crypto.privateDecrypt(
          {
            key: serverPrivateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
          },
          encryptedBuf,
        );
        console.log("4. Отримано та розшифровано premaster secret");

        //  Генерація сесійного ключа
        sessionKey = crypto
          .createHmac("sha256", premasterSecret)
          .update(Buffer.concat([clientRandom, serverRandom]))
          .digest();
        console.log("5. Згенеровано сесійний ключ");

        state = "WAIT_FINISHED";
      } else if (state === "WAIT_FINISHED" && msg.type === "ClientFinished") {
        //  Перевірка готовності
        const clientFinishedText = decryptAES(sessionKey, msg.payload);
        if (clientFinishedText !== "CLIENT_FINISHED_OK") {
          console.log("Помилка авторизації клієнта");
          socket.destroy();
          return;
        }
        console.log("6. Отримано підтвердження клієнта");

        const serverFinishedPayload = encryptAES(
          sessionKey,
          "SERVER_FINISHED_OK",
        );
        socket.write(
          JSON.stringify({
            type: "ServerFinished",
            payload: serverFinishedPayload,
          }) + "\n",
        );
        console.log("6. Відправлено підтвердження сервера");

        state = "SECURE_CHANNEL";
        console.log("7. Рукостискання завершено. Канал захищено.\n");
      } else if (state === "SECURE_CHANNEL" && msg.type === "AppData") {
        //  Безпечна передача даних
        const decryptedMessage = decryptAES(sessionKey, msg.payload);
        console.log(`Отримано повідомлення: "${decryptedMessage}"`);

        const responsePayload = encryptAES(
          sessionKey,
          "Сервер підтверджує отримання файлу/повідомлення.",
        );
        socket.write(
          JSON.stringify({ type: "AppData", payload: responsePayload }) + "\n",
        );
      }
    }
  });

  socket.on("end", () => {
    console.log("Клієнт відключився.");
  });
});

server.listen(PORT, () => {
  console.log(`Сервер працює на порту ${PORT}...`);
});
