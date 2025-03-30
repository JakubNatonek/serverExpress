const express =  require('express');
const app = express();
const port = process.env.PORT || 8080;

const cors = require('cors');
app.use(cors());
app.use(cors({ origin: 'http://localhost:8100' }));

app.use(express.json());

app.listen(
    port,
    () => console.log(`http://localhost:${port}`)
);

app.get('/test', (req, res) => {
    res.status(200).send({
        users:["userOne", "userTwo", "userThre"]
    });
});

// Przykładowa tabela użytkowników i haseł
const table = {
    users: ["ww@ww.pl"],
    passw: ["123456"]
  };

const crypto = require("crypto");
const secretKey = Buffer.from("my_secret_key_16"); // 16 bajtów

function decryptData(iv, encryptedData) {
  console.log("Received IV:", iv);
  console.log("Received Encrypted Data:", encryptedData);
  const decipher = crypto.createDecipheriv("aes-128-cbc", secretKey, Buffer.from(iv));
  let decrypted = decipher.update(Buffer.from(encryptedData));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  console.log("Decrypted Data:", decrypted.toString());
  return JSON.parse(decrypted.toString());
}

app.post("/register", (req, res) => {
  try {
    console.log("Incoming request body:", req.body);
    const { iv, data } = req.body;
    const decryptedData = decryptData(iv, data);
    console.log("Decrypted user data:", decryptedData);
    table.users.push(String(decryptedData.user));
    table.passw.push(String(decryptedData.password));
    res.json({ message: "Użytkownik zarejestrowany!" });
  } catch (error) {
    console.error("Decryption error:", error);
    res.status(500).json({ message: "Błąd dekodowania danych" });
  }
});