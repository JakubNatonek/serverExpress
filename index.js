const express =  require('express');
const mysql = require('mysql2/promise');

require('dotenv').config();
const app = express();
const port = process.env.PORT || 8080;

const cors = require('cors');
app.use(cors()); //wszystko
app.use(cors({ origin: 'http://localhost:8100' })); //apka

const jwt = require("jsonwebtoken"); // JSON web token -------------------

const JWT_SECRET = process.env.JWT_SECRET; 

function generateToken(email, userType) {
  return jwt.sign({ email, userType }, JWT_SECRET, { expiresIn: "1h" }); 
}

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
const secretKey = process.env.SECRET_KEY;

function decryptData(iv, encryptedData) {
  //console.log("Received IV:", iv);
  //console.log("Received Encrypted Data:", encryptedData);
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

const login_user = async (email, haslo_hash) => {
  const connection = await connectDB();
  const query = 'SELECT typ_uzytkownika FROM uzytkownicy WHERE email = ? AND haslo_hash = ?';

  try {
    const [results] = await connection.execute(query, [email, haslo_hash]);
    await connection.end();
    return results[0]; // Zwraca typ użytkownika
  } catch (err) {
    await connection.end();
    throw err;
  }
};

app.post("/login", async (req, res) => {
  try {
    const { iv, data } = req.body;
    const decryptedData = decryptData(iv, data);

    const email = decryptedData.user;
    const haslo_hash = decryptedData.password;

    try {
      const user = await login_user(email, haslo_hash);
      
      if (!user) {
        return res.status(400).json({ message: 'Niepoprawny adres e-mail lub hasło.' });
      }

      // Generowanie tokena JWT z rolą użytkownika
      const token = generateToken(email, user.typ_uzytkownika);

      return res.status(200).json({ message: 'Zalogowano pomyślnie!', token });
    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).json({ message: 'Wystąpił błąd podczas logowania' });
    }
  } catch (error) {
    console.error("Decryption error:", error);
    return res.status(500).json({ message: "Błąd dekodowania danych" });
  }
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Brak tokena" });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Nieprawidłowy token" });
    }
    req.user = user; // Dodanie danych użytkownika do obiektu `req`
    next();
  });
}

app.get('/users', authenticateToken, async (req, res) => {
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


//--------------------------------------------------------------------------------------------------------------------- Poczatek zmian

function authorizeRole(...allowedRoles) {
  return (req, res, next) => {
    const userType = req.user.userType;
    if (!allowedRoles.includes(userType)) {
      console.error("Brak dostępu dla roli:", userType);
      return res.status(403).json({ message: "Brak dostępu" });
    }
    next();
  };
}



// Dodaj nowego użytkownika
app.post('/users', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { email, imie, telefon, typ_uzytkownika, haslo } = req.body;
  if (!email || !haslo) return res.status(400).json({ message: "Email i hasło są wymagane" });
  try {
    const connection = await connectDB();
    const query = `
      INSERT INTO uzytkownicy (imie, email, telefon, haslo_hash, typ_uzytkownika, data_utworzenia)
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `;
    await connection.execute(query, [imie, email, telefon, haslo, typ_uzytkownika]);
    await connection.end();
    res.status(201).json({ message: "Użytkownik dodany" });
  } catch (err) {
    res.status(500).json({ message: "Błąd podczas dodawania użytkownika" });
  }
});

// Edytuj użytkownika
app.put('/users/:email', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { email } = req.params;
  const { imie = "", telefon = "", typ_uzytkownika = "" } = req.body;
  try {
    const connection = await connectDB();
    const query = `
      UPDATE uzytkownicy SET imie=?, telefon=?, typ_uzytkownika=?
      WHERE email=?
    `;
    const [result] = await connection.execute(query, [imie, telefon, typ_uzytkownika, email]);
    await connection.end();
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Nie znaleziono użytkownika" });
    }
    res.status(200).json({ message: "Użytkownik zaktualizowany" });
  } catch (err) {
    res.status(500).json({ message: "Błąd podczas aktualizacji użytkownika" });
  }
});

// Usuń użytkownika
app.delete('/users/:email', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { email } = req.params;
  try {
    const connection = await connectDB();
    const [result] = await connection.execute('DELETE FROM uzytkownicy WHERE email=?', [email]);
    await connection.end();
    if (result.affectedRows === 0) return res.status(404).json({ message: "Nie znaleziono użytkownika" });
    res.status(200).json({ message: "Użytkownik usunięty" });
  } catch (err) {
    res.status(500).json({ message: "Błąd podczas usuwania użytkownika" });
  }
});

//--------------------------------------------------------------------------------------------------------------------- Koniec zmian

//--------------------------------------------------------------------------------------------------------------------- Poczatek zmian ACL
