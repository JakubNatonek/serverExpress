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

function generateToken(email, userType, id) {
  return jwt.sign({ email, userType, id }, JWT_SECRET, { expiresIn: "1h" });
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
    // console.log("Incoming request body:", req.body);
    const { iv, data } = req.body;
    const decryptedData = decryptData(iv, data);
    // console.log("Decrypted user data:", decryptedData);

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

      // If user does not exist, add to database
      const result = await add_user(email, haslo_hash);
      return res
        .status(201)
        .json({ message: "Użytkownik dodany pomyślnie!", result });
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
    // console.log(decryptedData)
    const email = decryptedData.user;
    const haslo_hash = decryptedData.password;

    try {
      const user = await login_user(email, haslo_hash);
      // console.log(user);
      if (!user) {
        return res
          .status(400)
          .json({ message: "Niepoprawny adres e-mail lub hasło." });
      }
      // console.log(user.typ_uzytkownika);
      // Generowanie tokena JWT z rolą użytkownika
      const token = generateToken(email, user.typ_uzytkownika, user.id);

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

app.get(
  "/users",
  authenticateToken,
  authorizeRole("admin"),
  async (req, res) => {
    try {
      const connection = await connectDB();
      const [rows] = await connection.execute("SELECT * FROM uzytkownicy");
      await connection.end();
      res.json(rows);
    } catch (err) {
      console.error("Error fetching data: ", err);
      return res
        .status(500)
        .json({ message: "Błąd" });
    }
  }
);

//--------------------------------------------------------------------------------------------------------------------- Poczatek zmian

function authorizeRole(...allowedRoles) {
  return (req, res, next) => {
    const userType = req.user.userType;
    // console.log(req.user)
    if (!allowedRoles.includes(userType)) {
      console.error("Brak dostępu dla roli:", userType);
      return res.status(403).json({ message: "Brak dostępu" });
    }
    next();
  };
}

// Dodaj nowego użytkownika
app.post(
  "/users",
  authenticateToken,
  authorizeRole("admin"),
  async (req, res) => {
    const { email, imie, telefon, typ_uzytkownika, haslo } = req.body;
    if (!email || !haslo)
      return res.status(400).json({ message: "Email i hasło są wymagane" });
    try {
      const connection = await connectDB();
      const query = `
      INSERT INTO uzytkownicy (imie, email, telefon, haslo_hash, typ_uzytkownika, data_utworzenia)
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `;
      await connection.execute(query, [
        imie,
        email,
        telefon,
        haslo,
        typ_uzytkownika,
      ]);
      await connection.end();
      res.status(201).json({ message: "Użytkownik dodany" });
    } catch (err) {
      res.status(500).json({ message: "Błąd podczas dodawania użytkownika" });
    }
  }
);

// Edytuj użytkownika
app.put(
  "/users/:email",
  authenticateToken,
  authorizeRole("admin"),
  async (req, res) => {
    const { email } = req.params;
    const { imie = "", telefon = "", typ_uzytkownika = "" } = req.body;
    try {
      const connection = await connectDB();
      const query = `
      UPDATE uzytkownicy SET imie=?, telefon=?, typ_uzytkownika=?
      WHERE email=?
    `;
      const [result] = await connection.execute(query, [
        imie,
        telefon,
        typ_uzytkownika,
        email,
      ]);
      await connection.end();
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Nie znaleziono użytkownika" });
      }
      res.status(200).json({ message: "Użytkownik zaktualizowany" });
    } catch (err) {
      res
        .status(500)
        .json({ message: "Błąd podczas aktualizacji użytkownika" });
    }
  }
);

// Usuń użytkownika
app.delete(
  "/users/:email",
  authenticateToken,
  authorizeRole("admin"),
  async (req, res) => {
    const { email } = req.params;
    try {
      const connection = await connectDB();
      const [result] = await connection.execute(
        "DELETE FROM uzytkownicy WHERE email=?",
        [email]
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
  const promien = 5; // domyślnie 5 km
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
          WHERE l1.uzytkownik_id = ?
            AND u.typ_uzytkownika = 'kierowca'
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