const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mysql = require("mysql2/promise");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 8080;

const cors = require("cors");
app.use(cors()); //wszystko
app.use(cors({ origin: "http://localhost:8100" })); //apka

const jwt = require("jsonwebtoken"); // JSON web token -------------------

const JWT_SECRET = process.env.JWT_SECRET;

function generateToken(email, roleId, id) {
  return jwt.sign({ email, roleId, id }, JWT_SECRET, { expiresIn: "1h" });
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

const crypto = require("crypto");
const secretKey = process.env.SECRET_KEY;

function decryptData(iv, encryptedData) {
  //console.log("Received IV:", iv);
  //console.log("Received Encrypted Data:", encryptedData);
  const decipher = crypto.createDecipheriv(
    "aes-128-cbc",
    secretKey,
    Buffer.from(iv)
  );
  let decrypted = decipher.update(Buffer.from(encryptedData));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  // console.log("Decrypted Data:", decrypted.toString());
  return JSON.parse(decrypted.toString());
}

async function generateKey() {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secretKey), // 16 bajtów
    { name: "AES-CBC" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptData(data) {
  const key = await generateKey();
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    key,
    new TextEncoder().encode(JSON.stringify(data))
  );
  return { iv: Array.from(iv), data: Array.from(new Uint8Array(encrypted)) };
}

// app.get('/users', async (req, res) => {
//   try {
//     const connection = await connectDB();
//     const [rows] = await connection.execute('SELECT * FROM uzytkownicy');
//     await connection.end();
//     res.json(rows);
//   } catch (err) {
//     console.error('Error fetching data: ', err);
//     res.status(500).send('Server Error');
//   }
// });

const add_user = async (email, haslo_hash) => {
  const connection = await connectDB();
  const query = `
    INSERT INTO uzytkownicy (imie, email, telefon, haslo_hash, typ_uzytkownika, data_utworzenia) 
    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  `;

  const values = ["NULL", email, "NULL", haslo_hash, "kierowca"];

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
  const query = "SELECT COUNT(*) AS count FROM uzytkownicy WHERE email = ?";

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
    const { iv, data } = req.body;
    const decryptedData = decryptData(iv, data);

    const email = decryptedData.user;
    const haslo_hash = decryptedData.password;

    try {
      // Check if user already exists
      const exist = await does_user_exist(email);

      if (exist) {
        return res
          .status(400)
          .json({ message: "Użytkownik o tym adresie e-mail już istnieje." });
      }

      // Dodaj użytkownika do bazy
      const connection = await connectDB();
      const [userResult] = await connection.execute(
        `INSERT INTO uzytkownicy (imie, email, telefon, haslo_hash, typ_uzytkownika, data_utworzenia) 
         VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
        ["NULL", email, "NULL", haslo_hash, "pasażer"]
      );

      const userId = userResult.insertId;

      // Dodaj rolę do rola_as_uzytkownik (domyślnie pasażer = 2)
      await connection.execute(
        `INSERT INTO rola_as_uzytkownik (uzytkownik_id, rola_id) VALUES (?, ?)`,
        [userId, 2]
      );

      await connection.end();

      return res
        .status(201)
        .json({ message: "Użytkownik dodany pomyślnie!", userId });
    } catch (err) {
      console.error("Błąd podczas dodawania użytkownika:", err);
      return res
        .status(500)
        .json({ message: "Wystąpił błąd podczas dodawania użytkownika" });
    }
  } catch (error) {
    console.error("Decryption error:", error);
    return res.status(500).json({ message: "Błąd dekodowania danych" });
  }
});

const login_user = async (email, haslo_hash) => {
  const connection = await connectDB();
  const query = "SELECT * FROM uzytkownicy WHERE email = ? AND haslo_hash = ?";

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
        return res
          .status(400)
          .json({ message: "Niepoprawny adres e-mail lub hasło." });
      }

      // Otwórz nowe połączenie do pobrania roli
      const connection = await connectDB();
      const [roleRows] = await connection.execute(
        "SELECT rola_id FROM rola_as_uzytkownik WHERE uzytkownik_id = ?",
        [user.id]
      );
      await connection.end();

      const roleId = roleRows.length ? roleRows[0].rola_id : null;
      
      // Sprawdź czy konto nie jest zamknięte (rola_id = 4)
      if (roleId === 4) {
        return res
          .status(403)
          .json({ message: "Konto zostało zamknięte. Skontaktuj się z administratorem." });
      }
      
      const token = generateToken(email, roleId, user.id);

      return res.status(200).json({ message: "Zalogowano pomyślnie!", token });
    } catch (err) {
      console.error("Login error:", err);
      return res
        .status(500)
        .json({ message: "Wystąpił błąd podczas logowania" });
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



//--------------------------------------------------------------------------------------------------------------------- Poczatek zmian

function authorizeRole(...allowedRoleIds) {
  return (req, res, next) => {
    const userRoleId = req.user.roleId;
    if (!allowedRoleIds.includes(userRoleId)) {
      return res.status(403).json({ message: "Brak dostępu" });
    }
    next();
  };
}

// Pobierz wszystkie role (do selecta w panelu admina)
app.get("/roles", authenticateToken, async (req, res) => {
  try {
    const connection = await connectDB();
    const [rows] = await connection.execute("SELECT ID as id, przywilej as nazwa FROM role");
    await connection.end();
    
    // Zaszyfruj dane przed wysłaniem
    const encryptedData = await encryptData(rows);
    res.json(encryptedData);
  } catch (err) {
    res.status(500).json({ message: "Błąd podczas pobierania ról" });
  }
});

// Pobierz użytkowników z nazwą roli (JOIN)
app.get(
  "/users",
  authenticateToken,
  authorizeRole(1),
  async (req, res) => {
    try {
      const connection = await connectDB();
      const [rows] = await connection.execute(`
        SELECT 
          u.id, u.imie, u.email, u.telefon, u.data_utworzenia,
          r.ID AS rola_id, r.przywilej AS rola_nazwa
        FROM uzytkownicy u
        LEFT JOIN rola_as_uzytkownik rau ON u.id = rau.uzytkownik_id
        LEFT JOIN role r ON rau.rola_id = r.ID
      `);
      await connection.end();
      
      // Szyfrowanie danych
      const encryptedData = await encryptData(rows);
      res.json(encryptedData);
    } catch (err) {
      console.error("Error fetching data: ", err);
      return res.status(500).json({ message: "Błąd" });
    }
  }
);

// Dodaj nowego użytkownika z rolą
app.post(
  "/users",
  authenticateToken,
  authorizeRole(1),
  async (req, res) => {
    try {
      // Odszyfrowanie danych
      const { iv, data } = req.body;
      const decryptedData = decryptData(iv, data);
      
      const { email, imie, telefon, haslo, rola_id } = decryptedData;
      if (!email || !haslo)
        return res.status(400).json({ message: "Email i hasło są wymagane" });
      
      const connection = await connectDB();
      // Dodaj użytkownika
      const [userResult] = await connection.execute(
        `INSERT INTO uzytkownicy (imie, email, telefon, haslo_hash, data_utworzenia)
         VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
        [imie, email, telefon, haslo]
      );
      const userId = userResult.insertId;
      // Dodaj rolę do rola_as_uzytkownik
      await connection.execute(
        `INSERT INTO rola_as_uzytkownik (uzytkownik_id, rola_id) VALUES (?, ?)`,
        [userId, rola_id || 2]
      );
      await connection.end();
      res.status(201).json({ message: "Użytkownik dodany" });
    } catch (err) {
      res.status(500).json({ message: "Błąd podczas dodawania użytkownika" });
    }
  }
);

// Edytuj użytkownika (dane)
app.put(
  "/users/:email",
  authenticateToken,
  authorizeRole(1),
  async (req, res) => {
    try {
      const { email } = req.params;
      
      // Odszyfrowanie danych
      const { iv, data } = req.body;
      const decryptedData = decryptData(iv, data);
      
      const { imie = "", telefon = "" } = decryptedData;
      
      const connection = await connectDB();
      const query = `
        UPDATE uzytkownicy SET imie=?, telefon=?
        WHERE email=?
      `;
      const [result] = await connection.execute(query, [
        imie,
        telefon,
        email,
      ]);
      await connection.end();
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Nie znaleziono użytkownika" });
      }
      res.status(200).json({ message: "Użytkownik zaktualizowany" });
    } catch (err) {
      res.status(500).json({ message: "Błąd podczas aktualizacji użytkownika" });
    }
  }
);

// Edytuj rolę użytkownika (rola_as_uzytkownik)
app.put(
  "/users/:email/role",
  authenticateToken,
  authorizeRole(1),
  async (req, res) => {
    try {
      const { email } = req.params;
      
      // Odszyfrowanie danych
      const { iv, data } = req.body;
      const decryptedData = decryptData(iv, data);
      
      const { rola_id } = decryptedData;
      
      if (!rola_id) return res.status(400).json({ message: "Brak roli" });
      
      const connection = await connectDB();
      // Pobierz id użytkownika
      const [userRows] = await connection.execute(
        "SELECT id FROM uzytkownicy WHERE email=?",
        [email]
      );
      if (!userRows.length) {
        await connection.end();
        return res.status(404).json({ message: "Nie znaleziono użytkownika" });
      }
      const userId = userRows[0].id;
      // Zmień rolę
      await connection.execute(
        `UPDATE rola_as_uzytkownik SET rola_id=? WHERE uzytkownik_id=?`,
        [rola_id, userId]
      );
      await connection.end();
      res.status(200).json({ message: "Rola użytkownika zaktualizowana" });
    } catch (err) {
      res.status(500).json({ message: "Błąd podczas aktualizacji roli" });
    }
  }
);

// Usuń użytkownika (usuń też rolę)
app.delete(
  "/users/:email",
  authenticateToken,
  authorizeRole(1),
  async (req, res) => {
    try {
      const { email } = req.params;
      
      // W przypadku DELETE może nie być body, ale gdyby było, można odszyfrować
      let decryptedData = {};
      if (req.body && req.body.iv && req.body.data) {
        decryptedData = decryptData(req.body.iv, req.body.data);
      }
      
      const connection = await connectDB();
      // Pobierz id użytkownika
      const [userRows] = await connection.execute(
        "SELECT id FROM uzytkownicy WHERE email=?",
        [email]
      );
      if (!userRows.length) {
        await connection.end();
        return res.status(404).json({ message: "Nie znaleziono użytkownika" });
      }
      const userId = userRows[0].id;
      // Usuń rolę
      await connection.execute(
        "DELETE FROM rola_as_uzytkownik WHERE uzytkownik_id=?",
        [userId]
      );
      // Usuń użytkownika
      const [result] = await connection.execute(
        "DELETE FROM uzytkownicy WHERE id=?",
        [userId]
      );
      await connection.end();
      if (result.affectedRows === 0)
        return res.status(404).json({ message: "Nie znaleziono użytkownika" });
      res.status(200).json({ message: "Użytkownik usunięty" });
    } catch (err) {
      res.status(500).json({ message: "Błąd podczas usuwania użytkownika" });
    }
  }
);

//--------------------------------------------------------------------------------------------------------------------- Koniec zmian

// Zapis lokalizacji użytkownika
app.post("/lokalizacja", authenticateToken, async (req, res) => {
  const user = req.user;
  // console.log(user);
  const { iv, data } = req.body;
  const decryptedData = decryptData(iv, data);
  // console.log(decryptedData)
  const uzytkownik_id = user.id;
  const szerokosc_geo = decryptedData.szerokosc_geo;
  const dlugosc_geo = decryptedData.dlugosc_geo;
  if (!szerokosc_geo || !dlugosc_geo) {
    return res.status(400).json({ message: "Brak wymaganych danych" });
  }

  const query = `
      INSERT INTO lokalizacje (uzytkownik_id, szerokosc_geo, dlugosc_geo, zaktualizowano)
      VALUES (?, ?, ?, NOW())
      ON DUPLICATE KEY UPDATE
        szerokosc_geo = VALUES(szerokosc_geo),
        dlugosc_geo = VALUES(dlugosc_geo),
        zaktualizowano = NOW()
    `;
  const connection = await connectDB();
  try {
    await connection.execute(query, [
      uzytkownik_id,
      szerokosc_geo,
      dlugosc_geo,
    ]);
    await connection.end();
    res.json({ message: "Lokalizacja zapisana" });
  } catch (err) {
    console.error(err);
    await connection.end();
    res.status(500).json({ message: "Błąd serwera" });
  }
});

app.get("/bliscy/", authenticateToken, async (req, res) => {
  const user = req.user;
  // const { iv, data } = req.body;
  // const decryptedData = decryptData(iv, data);
  // console.log(user)
  // console.log(req)
  const uzytkownik_id = user.id;
  const promien = 100; // domyślnie 5 km
  const query = `
    SELECT 
      l2.uzytkownik_id,
      u.imie AS imie_kierowcy,
      (
        6371 * acos(
          cos(radians(l1.szerokosc_geo)) * 
          cos(radians(l2.szerokosc_geo)) *
          cos(radians(l2.dlugosc_geo) - radians(l1.dlugosc_geo)) +
          sin(radians(l1.szerokosc_geo)) *
          sin(radians(l2.szerokosc_geo))
        )
      ) AS dystans_km
    FROM lokalizacje l1
    JOIN lokalizacje l2 ON l1.uzytkownik_id != l2.uzytkownik_id
    JOIN uzytkownicy u ON l2.uzytkownik_id = u.id
    JOIN rola_as_uzytkownik rau ON u.id = rau.uzytkownik_id
    WHERE l1.uzytkownik_id = ?
      AND rau.rola_id = 3 -- Tylko użytkownicy z rolą kierowca
    HAVING dystans_km < ?
    ORDER BY dystans_km ASC
    LIMIT 10;
    `;
  const connection = await connectDB();
  try {
    const [rows] = await connection.execute(query, [uzytkownik_id, promien]);
    // console.log(rows);
    await connection.end();
    const data = await encryptData(rows);
    res.json(data); // Zwraca listę: { uzytkownik_id, dystans_km }
  } catch (err) {
    console.error(err);
    await connection.end();
    res.status(500).json({ message: "Błąd serwera" });
  }
});


app.post("/zlecenia", authenticateToken, async (req, res) => {
  const user = req.user; // Dane użytkownika z tokena
  const { iv, data } = req.body;

  try {
    // Odszyfrowanie danych
    const decryptedData = decryptData(iv, data);
    // console.log(decryptedData);
    const { kierowca_id, dystans_km, trasa_przejazdu, cena, status_id } =
      decryptedData;

    if (
      !kierowca_id ||
      !dystans_km ||
      !trasa_przejazdu ||
      !cena ||
      !status_id
    ) {
      return res.status(400).json({ message: "Brak wymaganych danych" });
    }

    const connection = await connectDB();

    // Sprawdzenie, czy pasażer ma już aktywny przejazd
    const checkQuery = `
      SELECT COUNT(*) AS activeRides
      FROM przejazdy
      WHERE pasazer_id = ? AND status_id IN (1, 2)
    `;
    const [checkResult] = await connection.execute(checkQuery, [user.id]);

    if (checkResult[0].activeRides > 0) {
      await connection.end();
      return res
        .status(400)
        .json({ message: "Masz już aktywny przejazd. Nie możesz zamówić nowego." });
    }

    // Sprawdzenie, czy kierowca ma już przejazd o statusie 2
    const checkDriverQuery = `
      SELECT COUNT(*) AS activeDriverRides
      FROM przejazdy
      WHERE kierowca_id = ? AND status_id = 2
    `;
    const [driverResult] = await connection.execute(checkDriverQuery, [kierowca_id]);

    if (driverResult[0].activeDriverRides > 0) {
      await connection.end();
      return res
        .status(400)
        .json({ message: "Wybrany kierowca ma już aktywny przejazd. Nie można przypisać nowego." });
    }


    // Dodanie nowego przejazdu
    const query = `
      INSERT INTO przejazdy (pasazer_id, kierowca_id, dystans_km, trasa_przejazdu, cena, data_zamowienia, status_id)
      VALUES (?, ?, ?, ?, ?, NOW(), ?)
    `;

    try {
      await connection.execute(query, [
        user.id, // pasazer_id
        kierowca_id,
        dystans_km,
        JSON.stringify(trasa_przejazdu), // Przechowywanie geometrii jako JSON
        cena,
        status_id,
      ]);
      await connection.end();
      res.status(201).json({ message: "Zlecenie zostało zapisane" });
    } catch (err) {
      console.error("Błąd podczas zapisywania zlecenia:", err);
      await connection.end();
      res.status(500).json({ message: "Błąd serwera" });
    }
  } catch (err) {
    console.error("Błąd dekodowania danych:", err);
    res.status(500).json({ message: "Błąd dekodowania danych" });
  }
});

app.get("/zlecenia", authenticateToken, async (req, res) => {
  const userId = req.user.id; // ID użytkownika z tokena
  const connection = await connectDB();

  const query = `
    SELECT 
      p.id AS zlecenie_id,
      p.pasazer_id,
      pas.imie AS pasazer_imie, -- Imię pasażera
      p.kierowca_id,
      kier.imie AS kierowca_imie, -- Imię kierowcy
      p.dystans_km,
      p.trasa_przejazdu,
      p.cena,
      p.data_zamowienia,
      p.data_zakonczenia,
      s.nazwa AS status
    FROM przejazdy p
    JOIN uzytkownicy pas ON p.pasazer_id = pas.id -- Dołączenie danych pasażera
    JOIN uzytkownicy kier ON p.kierowca_id = kier.id -- Dołączenie danych kierowcy
    JOIN statusy_przejazdu s ON p.status_id = s.id -- Dołączenie statusu
    WHERE p.pasazer_id = ? OR p.kierowca_id = ?
    ORDER BY p.data_zamowienia DESC
  `;

  try {
    const [rows] = await connection.execute(query, [userId, userId]);
    await connection.end();
    const data = await encryptData(rows);
    res.status(200).json(data); // Zwraca listę zleceń użytkownika
  } catch (err) {
    console.error("Błąd podczas pobierania zleceń:", err);
    await connection.end();
    res.status(500).json({ message: "Błąd serwera" });
  }
});

app.put("/zlecenia/:id/status", authenticateToken, async (req, res) => {
  const zlecenieId = req.params.id; // ID zlecenia z parametru URL
  const { iv, data } = req.body; // Odbieranie zaszyfrowanych danych

  if (!iv || !data) {
    return res.status(400).json({ message: "Brak danych do zaktualizowania" });
  }

  try {
    // Deszyfrowanie danych
    const decryptedData = decryptData(iv, data);
    const { status_id } = decryptedData;
    console.log(decryptedData)

    if (!status_id) {
      return res.status(400).json({ message: "Brak statusu do zaktualizowania" });
    }

    const connection = await connectDB();
    const query = `
      UPDATE przejazdy
      SET status_id = ?
      WHERE id = ?
    `;

    try {
      const [result] = await connection.execute(query, [status_id, zlecenieId]);
      await connection.end();

      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Nie znaleziono zlecenia" });
      }

      res.status(200).json({ message: "Status zlecenia został zaktualizowany" });
    } catch (err) {
      console.error("Błąd podczas aktualizowania statusu zlecenia:", err);
      await connection.end();
      res.status(500).json({ message: "Błąd serwera" });
    }
  } catch (err) {
    console.error("Błąd dekodowania danych:", err);
    res.status(500).json({ message: "Błąd dekodowania danych" });
  }
});


//--------------------------------------------------------------------------------------------------------------------- Poczatek zmian ACL

//Socket.io

// Tworzymy serwer HTTP narazie jak co
app.get("/chats", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const connection = await connectDB();
  const query = `
    SELECT 
      p.id AS rideId,
      p.data_zamowienia,
      CASE 
        WHEN p.pasazer_id = ? THEN k.imie 
        ELSE pas.imie 
      END AS otherName
    FROM przejazdy p
    JOIN uzytkownicy k   ON k.id = p.kierowca_id
    JOIN uzytkownicy pas ON pas.id = p.pasazer_id
    WHERE (p.pasazer_id = ? OR p.kierowca_id = ?)
      AND p.data_zamowienia >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    ORDER BY p.data_zamowienia DESC
  `;
  try {
    const [rows] = await connection.execute(query, [
      userId,
      userId,
      userId,
    ]);
    await connection.end();
    // dla szyfracji na przyszłość
    const data = await encryptData(rows);
    return res.json(data);
    // jeżeli bedzie brak szyfracji
    // return res.json(rows);
  } catch (err) {
    console.error("Error fetching chats:", err);
    await connection.end();
    res.status(500).json({ message: "Błąd serwera" });
  }
});

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "http://localhost:8100", methods: ["GET","POST"] }
});

io.on("connection", (socket) => {
  console.log("Socket connected:", socket.id);

  socket.on("joinRoom", async ({ rideId }) => {
    const room = `ride-${rideId}`;
    socket.join(room);
  
    try {
      const conn = await connectDB();
      const [history] = await conn.execute(
        `SELECT 
           nadawca_email   AS senderEmail,
           tresc           AS message,
           czas            AS timestamp
         FROM wiadomosci
         WHERE przejazd_id = ?
         ORDER BY czas ASC`,
        [rideId]
      );
      await conn.end();
      socket.emit("chatHistory", history);
    } catch (err) {
      console.error("Error fetching chat history:", err);
    }
  });

  socket.on("sendMessage", async ({ rideId, senderEmail, message }) => {
    const ts = new Date()
      .toISOString()
      .slice(0, 19)
      .replace("T", " ");
    socket.broadcast
      .to(`ride-${rideId}`)
      .emit("receiveMessage", { senderEmail, message, timestamp: ts });

    (async () => {
      try {
        const conn = await connectDB();

        const [tripRows] = await conn.execute(
          "SELECT pasazer_id, kierowca_id FROM przejazdy WHERE id = ?",
          [rideId]
        );
        if (!tripRows.length) { await conn.end(); return; }
        const { pasazer_id, kierowca_id } = tripRows[0];

        const [pasRows] = await conn.execute(
          "SELECT email FROM uzytkownicy WHERE id = ?",
          [pasazer_id]
        );
        const [kierRows] = await conn.execute(
          "SELECT email FROM uzytkownicy WHERE id = ?",
          [kierowca_id]
        );
        const pasEmail  = pasRows[0]?.email  ?? null;
        const kierEmail = kierRows[0]?.email ?? null;

        const receiverEmail = (senderEmail === pasEmail ? kierEmail : pasEmail) ?? null;

        const from    = senderEmail    ?? null;
        const to      = receiverEmail  ?? null;
        const content = message        ?? "";

        await conn.execute(
          `INSERT INTO wiadomosci
             (nadawca_email, odbiorca_email, przejazd_id, tresc, czas)
           VALUES (?,             ?,               ?,           ?,    ?)`,
          [from, to, rideId, content, ts]
        );
        await conn.end();
      } catch (err) {
        console.error("Błąd zapisu czatu:", err);
      }
    })();
  });
  socket.on("disconnect", () => {
  });
});

server.listen(port, () =>
  console.log(`Serwer działa na porcie http://localhost:${port}`)
);

//--------------------------------------------------------------------------------------------------------------------- Poczatek zmian PROFIL

// Pobierz dane profilu zalogowanego użytkownika
app.get("/profile", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const connection = await connectDB();
    const [rows] = await connection.execute(
      `SELECT imie, email, telefon, data_utworzenia FROM uzytkownicy WHERE id=?`,
      [userId]
    );
    await connection.end();
    if (!rows.length) return res.status(404).json({ message: "Nie znaleziono użytkownika" });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ message: "Błąd pobierania profilu" });
  }
});

// Edytuj dane profilu (imię, telefon)
app.put("/profile", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { imie = "", telefon = "" } = req.body;
  try {
    const connection = await connectDB();
    await connection.execute(
      `UPDATE uzytkownicy SET imie=?, telefon=? WHERE id=?`,
      [imie, telefon, userId]
    );
    await connection.end();
    res.status(200).json({ message: "Profil zaktualizowany" });
  } catch (err) {
    res.status(500).json({ message: "Błąd zapisu profilu" });
  }
});



// Usuń konto użytkownika
app.delete("/profile", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const connection = await connectDB();
    await connection.execute(
      "DELETE FROM rola_as_uzytkownik WHERE uzytkownik_id=?",
      [userId]
    );
    await connection.execute(
      "DELETE FROM uzytkownicy WHERE id=?",
      [userId]
    );
    await connection.end();
    res.json({ message: "Konto usunięte" });
  } catch (err) {
    res.status(500).json({ message: "Błąd usuwania konta" });
  }
});


app.put("/profile/password", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ message: "Brak danych" });
  }
  try {
    const connection = await connectDB();
    // Pobierz aktualny hash hasła
    const [rows] = await connection.execute(
      "SELECT haslo_hash FROM uzytkownicy WHERE id=?",
      [userId]
    );
    if (!rows.length) {
      await connection.end();
      return res.status(404).json({ message: "Nie znaleziono użytkownika" });
    }
    const currentHash = rows[0].haslo_hash;
    if (currentHash !== oldPassword) {
      await connection.end();
      return res.status(400).json({ message: "Stare hasło nieprawidłowe" });
    }
    // Zmień hasło na nowe (już zahashowane)
    await connection.execute(
      "UPDATE uzytkownicy SET haslo_hash=? WHERE id=?",
      [newPassword, userId]
    );
    await connection.end();
    res.status(200).json({ message: "Hasło zmienione" });
  } catch (err) {
    res.status(500).json({ message: "Błąd zmiany hasła" });
  }
});

//--------------------------------------------------------------------------------------------------------------------- Koniec zmian PROFIL


//--------------------------------------------------------------------------------------------------------------------- Poczatek zmian ADMIN-Przeajzdy

app.get(
  "/admin/rides",
  authenticateToken,
  authorizeRole(1),
  async (req, res) => {
    try {
      const connection = await connectDB();
      const query = `
        SELECT 
          p.id, 
          p.pasazer_id,
          pas.imie AS pasazer_imie,
          pas.email AS pasazer_email,
          p.kierowca_id,
          kier.imie AS kierowca_imie,
          kier.email AS kierowca_email,
          p.dystans_km,
          p.cena,
          p.data_zamowienia,
          p.data_rozpoczecia,
          p.data_zakonczenia,
          s.nazwa AS status,
          s.id AS status_id
        FROM przejazdy p
        JOIN uzytkownicy pas ON p.pasazer_id = pas.id
        JOIN uzytkownicy kier ON p.kierowca_id = kier.id
        JOIN statusy_przejazdu s ON p.status_id = s.id
        ORDER BY p.data_zamowienia DESC
      `;
      const [rows] = await connection.execute(query);
      await connection.end();
      const data = await encryptData(rows);
      res.json(data);
    } catch (err) {
      console.error("Error fetching rides:", err);
      res.status(500).json({ message: "Błąd serwera" });
    }
  }
);


app.get(
  "/admin/rides/:id",
  authenticateToken,
  authorizeRole(1),
  async (req, res) => {
    try {
      const rideId = req.params.id;
      const connection = await connectDB();
      const query = `
        SELECT 
          p.*,
          pas.imie AS pasazer_imie,
          pas.email AS pasazer_email,
          kier.imie AS kierowca_imie,
          kier.email AS kierowca_email,
          s.nazwa AS status_nazwa
        FROM przejazdy p
        JOIN uzytkownicy pas ON p.pasazer_id = pas.id
        JOIN uzytkownicy kier ON p.kierowca_id = kier.id
        JOIN statusy_przejazdu s ON p.status_id = s.id
        WHERE p.id = ?
      `;
      const [rows] = await connection.execute(query, [rideId]);
      await connection.end();
      
      if (!rows.length) {
        return res.status(404).json({ message: "Przejazd nie istnieje" });
      }
      
      // Upewniamy się, że trasa_przejazdu jest w odpowiednim formacie
      const rideData = rows[0];
      
      // Jeśli trasa_przejazdu jest ciągiem JSON, zamień go na ciąg tekstowy
      if (typeof rideData.trasa_przejazdu === 'string') {
        try {
          // Sprawdź, czy to możliwy JSON string
          if (rideData.trasa_przejazdu.startsWith('{') || rideData.trasa_przejazdu.startsWith('[')) {
            // Jeśli to JSON, parsuj go, aby uzyskać wartość polyline
            const parsedRoute = JSON.parse(rideData.trasa_przejazdu);
            // Zakładamy, że polyline jest przechowywane jako string wewnątrz JSON
            if (parsedRoute.polyline) {
              rideData.trasa_przejazdu = parsedRoute.polyline;
            }
          }
          // W przeciwnym razie pozostaw jak jest - może to już być ciąg polyline
        } catch (e) {
          // Jeśli parsowanie nie powiodło się, pozostawiamy oryginalną wartość
        }
      }
      
      const data = await encryptData(rideData);
      res.json(data);
    } catch (err) {
      res.status(500).json({ message: "Błąd serwera" });
    }
  }
);


app.put(
  "/admin/rides/:id",
  authenticateToken,
  authorizeRole(1),
  async (req, res) => {
    try {
      const rideId = req.params.id;
      
      // Sprawdzamy czy dane są w oczekiwanym formacie
      if (!req.body || !req.body.iv || !req.body.data) {
        return res.status(400).json({ message: "Nieprawidłowy format danych" });
      }
      
      const { iv, data } = req.body;
      
      try {
        const decryptedData = decryptData(iv, data);
        
        // Weryfikacja czy mamy wszystkie wymagane pola
        const {
          pasazer_id,
          kierowca_id,
          cena,
          dystans_km,
          status_id,
          data_rozpoczecia,
          data_zakonczenia
        } = decryptedData;
        
        if (!cena || !dystans_km || !status_id) {
          return res.status(400).json({ message: "Brakuje wymaganych pól" });
        }
        
        const connection = await connectDB();
        
        // Znajdź istniejący przejazd, aby zachować pola, których nie edytujemy
        const [existingRide] = await connection.execute(
          "SELECT * FROM przejazdy WHERE id = ?",
          [rideId]
        );
        
        if (!existingRide.length) {
          await connection.end();
          return res.status(404).json({ message: "Przejazd nie istnieje" });
        }
        
        // Aktualizuj tylko pola, które mogą być edytowane z frontu
        const query = `
          UPDATE przejazdy
          SET 
            cena = ?,
            dystans_km = ?,
            status_id = ?
          WHERE id = ?
        `;
        
        const [result] = await connection.execute(query, [
          cena,
          dystans_km,
          status_id,
          rideId
        ]);
        
        await connection.end();
        
        if (result.affectedRows === 0) {
          return res.status(404).json({ message: "Przejazd nie został zaktualizowany" });
        }
        
        res.json({ message: "Przejazd zaktualizowany" });
      } catch (decryptError) {
        return res.status(400).json({ message: "Błąd dekryptowania danych" });
      }
    } catch (err) {
      res.status(500).json({ message: "Błąd serwera" });
    }
  }
);

// Delete ride (admin only) - actually, just change status to 5
app.delete(
  "/admin/rides/:id",
  authenticateToken,
  authorizeRole(1),
  async (req, res) => {
    try {
      const rideId = req.params.id;
      const connection = await connectDB();
      
      // Zamiast usuwać, zmieniamy status na 5 (anulowany/zamknięty)
      const [result] = await connection.execute(
        "UPDATE przejazdy SET status_id = 5, data_zakonczenia = NOW() WHERE id = ?",
        [rideId]
      );
      
      await connection.end();
      
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Przejazd nie istnieje" });
      }
      
      res.json({ message: "Przejazd anulowany" });
    } catch (err) {
      res.status(500).json({ message: "Błąd serwera" });
    }
  }
);

// Pobierz podsumowanie statystyk przejazdów
app.get(
  "/admin/rides/stats/summary",
  authenticateToken,
  authorizeRole(1),
  async (req, res) => {
    try {
      const connection = await connectDB();
      const query = `
        SELECT
          COUNT(CASE WHEN status_id = 3 THEN 1 END) AS total_rides,
          COALESCE(SUM(CASE WHEN status_id = 3 THEN cena ELSE 0 END), 0) AS total_revenue,
          COALESCE(AVG(CASE WHEN status_id = 3 THEN cena END), 0) AS avg_price,
          COALESCE(AVG(CASE WHEN status_id = 3 THEN dystans_km END), 0) AS avg_distance,
          COUNT(CASE WHEN status_id = 1 THEN 1 END) AS pending_rides,
          COUNT(CASE WHEN status_id = 2 THEN 1 END) AS active_rides,
          COUNT(CASE WHEN status_id = 3 THEN 1 END) AS completed_rides,
          COUNT(CASE WHEN status_id = 4 THEN 1 END) AS cancelled_rides,
          COUNT(CASE WHEN status_id = 5 THEN 1 END) AS closed_rides
        FROM przejazdy
      `;
      
      const [rows] = await connection.execute(query);
      await connection.end();
      
      // Konwersja wartości na liczby przed wysłaniem do klienta
      const stats = rows[0];
      const formattedStats = {
        total_rides: Number(stats.total_rides),
        total_revenue: Number(stats.total_revenue).toFixed(2),
        avg_price: Number(stats.avg_price).toFixed(2),
        avg_distance: Number(stats.avg_distance).toFixed(2),
        pending_rides: Number(stats.pending_rides),
        active_rides: Number(stats.active_rides),
        completed_rides: Number(stats.completed_rides),
        cancelled_rides: Number(stats.cancelled_rides),
        closed_rides: Number(stats.closed_rides)
      };
      
      const data = await encryptData(formattedStats);
      res.json(data);
    } catch (err) {
      res.status(500).json({ message: "Błąd serwera" });
    }
  }
);

// Pobierz wszystkie dostępne statusy przejazdów
app.get(
  "/admin/ride-statuses",
  authenticateToken,
  authorizeRole(1),
  async (req, res) => {
    try {
      const connection = await connectDB();
      const [rows] = await connection.execute("SELECT * FROM statusy_przejazdu");
      await connection.end();
      res.json(rows);
    } catch (err) {
      res.status(500).json({ message: "Błąd serwera" });
    }
  }
);
