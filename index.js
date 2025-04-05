const express =  require('express');
const mysql = require('mysql2/promise');
require('dotenv').config();
const app = express();
const port = process.env.PORT || 8080;

const cors = require('cors');
app.use(cors());
app.use(cors({ origin: 'http://localhost:8100' }));

app.use(express.json());

async function connectDB() {
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });
  return connection;
}

app.listen(
    port,
    () => console.log(`http://localhost:${port}`)
);

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
app.get('/users', async (req, res) => {
  try {
    const connection = await connectDB();
    const [rows] = await connection.execute('SELECT * FROM uzytkownicy');
    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error('Error fetching data: ', err);
    res.status(500).send('Server Error');
  }
});

const add_user = async (email, haslo_hash) => {
  const connection = await connectDB();
  const query = `
    INSERT INTO uzytkownicy (imie, email, telefon, haslo_hash, typ_uzytkownika, data_utworzenia) 
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  `;

  const values = ['NULL', email, 'NULL', haslo_hash, "kierowca"];

  try {
    const [results] = await connection.execute(query, values);
    await connection.end();
    return results;
  } catch (err) {
    await connection.end();
    throw err; // Rethrow error to be handled by the caller
  }
};

const does_user_exist = async (email) => {
  const connection = await connectDB();
  const query = 'SELECT COUNT(*) AS count FROM uzytkownicy WHERE email = ?';

  try {
    const [results] = await connection.execute(query, [email]);
    await connection.end();
    return results[0].count > 0; // Return true if user exists
  } catch (err) {
    await connection.end();
    throw err; // Rethrow error to be handled by the caller
  }
};

app.post("/register", async (req, res) => {
  try {
    console.log("Incoming request body:", req.body);
    const { iv, data } = req.body;
    const decryptedData = decryptData(iv, data);
    console.log("Decrypted user data:", decryptedData);

    const email = decryptedData.user;
    const haslo_hash = decryptedData.password;

    try {
      // Check if user already exists
      const exist = await does_user_exist(email);
      
      if (exist) {
        return res.status(400).json({ message: 'Użytkownik o tym adresie e-mail już istnieje.' });
      }
  
      // If user does not exist, add to database
      const result = await add_user(email, haslo_hash);
      return res.status(201).json({ message: 'Użytkownik dodany pomyślnie!', result });

    } catch (err) {
      console.error('Błąd podczas dodawania użytkownika:', err);
      return res.status(500).json({ message: 'Wystąpił błąd podczas dodawania użytkownika' });
    }

  } catch (error) {
    console.error("Decryption error:", error);
    return res.status(500).json({ message: "Błąd dekodowania danych" });
  }
});