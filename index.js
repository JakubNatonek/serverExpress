const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mysql = require("mysql2/promise");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 8080;

const cors = require("cors");
app.use(cors()); //wszystko
// app.use(cors({ origin: "http://localhost:80" })); //apka

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

// ===Docker===check====
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

//============REGISTER======================

// Importuj modele Sequelize (dodaj na początku pliku, po innych importach)
const User = require("./models/User");
const Role = require("./models/Role");
const UserRole = require("./models/UserRole");
const sequelize = require('./models/Config');


app.post("/register", async (req, res) => {
  try {
    const { iv, data } = req.body;
    const decryptedData = decryptData(iv, data);

    const email = decryptedData.user;
    const haslo_hash = decryptedData.password;

    try {
      // Sprawdź czy użytkownik już istnieje
      const existingUser = await User.findOne({
        where: { email: email }
      });

      if (existingUser) {
        return res
          .status(400)
          .json({ message: "Użytkownik o tym adresie e-mail już istnieje." });
      }

      // Użyj transakcji Sequelize dla atomowej operacji
      const result = await sequelize.transaction(async (t) => {
        // Dodaj użytkownika używając Sequelize
        const newUser = await User.create({
          imie: "NULL",
          email: email,
          telefon: "NULL",
          haslo_hash: haslo_hash,
          data_utworzenia: sequelize.literal('CURRENT_TIMESTAMP')
        }, { transaction: t });

        // Dodaj rolę (domyślnie pasażer = 2)
        await UserRole.create({
          uzytkownik_id: newUser.id,
          rola_id: 2
        }, { transaction: t });

        return newUser;
      });

      // Generuj token dla nowego użytkownika (roleId = 2 pasażer)
      const token = generateToken(email, 2, result.id);

      return res
        .status(201)
        .json({ 
          message: "Użytkownik dodany pomyślnie!", 
          token: token  // Dodaję token do odpowiedzi
        });
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
//================TEST==LOGOWANIE==================

// Zastąp istniejący endpoint /login nowym kodem


app.post("/login", async (req, res) => {
  try {
    const { iv, data } = req.body;
    const decryptedData = decryptData(iv, data);
    const email = decryptedData.user;
    const haslo_hash = decryptedData.password;

    try {
      // Znajdź użytkownika po emailu i haśle
      const user = await User.findOne({
        where: {
          email: email,
          haslo_hash: haslo_hash,
        },
      });

      if (!user) {
        return res
          .status(400)
          .json({ message: "Niepoprawny adres e-mail lub hasło." });
      }

      // Pobierz rolę użytkownika
      const userRole = await UserRole.findOne({
        where: {
          uzytkownik_id: user.id,
        },
      });

      const roleId = userRole ? userRole.rola_id : null;

      // Sprawdź czy konto nie jest zamknięte (rola_id = 4)
      if (roleId === 4) {
        return res
          .status(403)
          .json({
            message:
              "Konto zostało zamknięte. Skontaktuj się z administratorem.",
          });
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



//==============KONIEC========================

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
    const [rows] = await connection.execute(
      "SELECT ID as id, przywilej as nazwa FROM role"
    );
    await connection.end();

    // Zaszyfruj dane przed wysłaniem
    const encryptedData = await encryptData(rows);
    res.json(encryptedData);
  } catch (err) {
    res.status(500).json({ message: "Błąd podczas pobierania ról" });
  }
});

// Pobierz użytkowników z nazwą roli (JOIN)
app.get("/users", authenticateToken, authorizeRole(1), async (req, res) => {
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
});

// Dodaj nowego użytkownika z rolą
app.post("/users", authenticateToken, authorizeRole(1), async (req, res) => {
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
});

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
      const [result] = await connection.execute(query, [imie, telefon, email]);
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
  const uzytkownik_id = user.id;
  const promien = 10; // domyślnie 10 km
  
  const query = `
    SELECT 
      l2.uzytkownik_id,
      u.imie AS imie_kierowcy,
      k.model_pojazdu,
      k.nr_rejestracyjny,
      k.kolor_pojazdu,
      k.ocena,
      l2.szerokosc_geo,
      l2.dlugosc_geo,
      l2.zaktualizowano,
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
    JOIN kierowcy k ON l2.uzytkownik_id = k.uzytkownik_id
    JOIN rola_as_uzytkownik rau ON u.id = rau.uzytkownik_id
    WHERE l1.uzytkownik_id = ?
      AND rau.rola_id = 3 -- Tylko użytkownicy z rolą kierowca
      AND l2.zaktualizowano >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
      AND NOT EXISTS (
        -- Wyklucz kierowców którzy mają aktywne zlecenie (status_id = 2) nie należące do tego użytkownika
        SELECT 1 FROM przejazdy p 
        WHERE p.kierowca_id = l2.uzytkownik_id 
          AND p.status_id = 2
          AND p.pasazer_id != ?
      )
    HAVING dystans_km < ?
    ORDER BY dystans_km ASC
    LIMIT 10;
  `;
    
  const connection = await connectDB();
  try {
    const [rows] = await connection.execute(query, [uzytkownik_id, uzytkownik_id, promien]);
    await connection.end();
    const data = await encryptData(rows);
    res.json(data);
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
        .json({
          message: "Masz już aktywny przejazd. Nie możesz zamówić nowego.",
        });
    }

    // Sprawdzenie, czy kierowca ma już przejazd o statusie 2
    const checkDriverQuery = `
      SELECT COUNT(*) AS activeDriverRides
      FROM przejazdy
      WHERE kierowca_id = ? AND status_id = 2
    `;
    const [driverResult] = await connection.execute(checkDriverQuery, [
      kierowca_id,
    ]);

    if (driverResult[0].activeDriverRides > 0) {
      await connection.end();
      return res
        .status(400)
        .json({
          message:
            "Wybrany kierowca ma już aktywny przejazd. Nie można przypisać nowego.",
        });
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
  const userId = req.user.id; // ID użytkownika z tokena
  const { iv, data } = req.body; // Odbieranie zaszyfrowanych danych

  if (!iv || !data) {
    return res.status(400).json({ message: "Brak danych do zaktualizowania" });
  }

  try {
    // Deszyfrowanie danych
    const decryptedData = decryptData(iv, data);
    const { status_id } = decryptedData;

    if (!status_id) {
      return res.status(400).json({ message: "Brak statusu do zaktualizowania" });
    }

    const connection = await connectDB();
    
    if (status_id === 3 || status_id === 4) {
      // Dla statusu "zakończony" lub "anulowany" ustawiamy datę zakończenia
      try {
        const [result] = await connection.execute(`
          UPDATE przejazdy
          SET status_id = ?, data_zakonczenia = NOW()
          WHERE id = ?
        `, [status_id, zlecenieId]);
        
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
    } else if (status_id === 2) {
      // Rozpoczynamy transakcję dla wielu operacji
      await connection.beginTransaction();
      
      try {
        const kierowcaId = userId;
        
        // 2. Dla statusu "w trakcie" ustawiamy datę rozpoczęcia dla bieżącego przejazdu
        await connection.execute(`
          UPDATE przejazdy
          SET status_id = ?, data_rozpoczecia = NOW()
          WHERE id = ? AND status_id = 1
        `, [status_id, zlecenieId]);
        
        // 3. Anuluj wszystkie inne oczekujące przejazdy (status_id = 1) tego kierowcy
        await connection.execute(`
          UPDATE przejazdy
          SET status_id = 4
          WHERE kierowca_id = ? 
          AND status_id = 1
          AND id != ?
        `, [kierowcaId, zlecenieId]);
        
        // Zatwierdź wszystkie zmiany
        await connection.commit();
        await connection.end();
        
        return res.status(200).json({ 
          message: "Status zlecenia został zaktualizowany, a inne oczekujące przejazdy anulowane" 
        });
      } catch (err) {
        // W przypadku błędu wycofaj zmiany
        await connection.rollback();
        await connection.end();
        console.error("Błąd podczas aktualizowania statusu:", err);
        return res.status(500).json({ message: "Błąd serwera" });
      }
    } else {
      // Dla pozostałych statusów - tylko zmiana statusu
      try {
        const [result] = await connection.execute(`
          UPDATE przejazdy
          SET status_id = ?
          WHERE id = ?
        `, [status_id, zlecenieId]);
        
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
    }
  } catch (err) {
    console.error("Błąd dekodowania danych:", err);
    res.status(500).json({ message: "Błąd dekodowania danych" });
  }
});

//--------------------------------------------------------------------------------------------------------------------- Poczatek zmian ACL

//Socket.io

// Tworzymy serwer HTTP narazie jak co
// Tworzymy serwer HTTP narazie jak co
app.get("/chats", authenticateToken, async (req, res) => {
  const { id: userId, userType } = req.user;
  const conn = await connectDB();

  let query;
  let params = [];

  if (userType === "admin") {
    // dla admina – wszystkie przejazdy z ostatnich 7 dni
    query = `
      SELECT 
        p.id                 AS rideId,
        p.data_zamowienia    AS data_zamowienia,
        CONCAT(uPas.imie, ' ↔ ', uKer.imie) AS otherName
      FROM przejazdy p
      JOIN uzytkownicy uKer ON uKer.id = p.kierowca_id
      JOIN uzytkownicy uPas ON uPas.id = p.pasazer_id
      WHERE p.data_zamowienia >= DATE_SUB(NOW(), INTERVAL 7 DAY)
      ORDER BY p.data_zamowienia DESC
    `;
  } else {
    // dla pasażera/kierowcy – tylko ich własne pokoje
    query = `
      SELECT 
        p.id              AS rideId,
        p.data_zamowienia AS data_zamowienia,
        CASE 
          WHEN p.pasazer_id = ? THEN k.imie 
          ELSE pas.imie 
        END AS otherName
      FROM przejazdy p
      JOIN uzytkownicy k   ON k.id   = p.kierowca_id
      JOIN uzytkownicy pas ON pas.id = p.pasazer_id
      WHERE (p.pasazer_id = ? OR p.kierowca_id = ?)
        AND p.data_zamowienia >= DATE_SUB(NOW(), INTERVAL 7 DAY)
      ORDER BY p.data_zamowienia DESC
    `;
    params = [userId, userId, userId];
  }

  try {
    const [rows] = params.length
      ? await conn.execute(query, params)
      : await conn.execute(query);
    await conn.end();
    // jeśli masz szyfrowanie – od tej linii szyfrujesz rows,
    // w przeciwnym wypadku po prostu res.json(rows)
    const data = await encryptData(rows);
    res.json(data);
  } catch (err) {
    await conn.end();
    console.error("Błąd pobierania czatów:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

// Get chat history for a specific ride
app.get("/chats/:rideId/history", authenticateToken, async (req, res) => {
  try {
    const { rideId } = req.params;
    const userId = req.user.id;

    // Verify user has access to this ride's chat
    const connection = await connectDB();
    const [rideCheck] = await connection.execute(
      "SELECT pasazer_id, kierowca_id FROM przejazdy WHERE id = ?",
      [rideId]
    );

    if (!rideCheck.length) {
      await connection.end();
      return res.status(404).json({ message: "Nie znaleziono przejazdu" });
    }

    const { pasazer_id, kierowca_id } = rideCheck[0];

    // Only allow passengers, drivers, or admins to access chat history
    if (
      userId !== pasazer_id &&
      userId !== kierowca_id &&
      req.user.roleId !== 1
    ) {
      await connection.end();
      return res.status(403).json({ message: "Brak uprawnień" });
    }

    // Fetch chat history
    const [history] = await connection.execute(
      `SELECT 
         nadawca_email   AS senderEmail,
         tresc           AS message,
         czas            AS timestamp
       FROM wiadomosci
       WHERE przejazd_id = ?
       ORDER BY czas ASC`,
      [rideId]
    );

    await connection.end();

    // Encrypt data before sending
    const encryptedData = await encryptData(history);
    res.json(encryptedData);
  } catch (err) {
    console.error("Error fetching chat history:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

// Delete chat and update ride status to 5 (closed)
app.delete("/chats/:id", authenticateToken, async (req, res) => {
  try {
    const chatId = req.params.id; // This is actually the ride ID
    const { reason } = req.body;

    // Verify the user has permission to delete this chat
    // (either the passenger or driver of this ride)
    const connection = await connectDB();
    const [rideCheck] = await connection.execute(
      "SELECT pasazer_id, kierowca_id FROM przejazdy WHERE id = ?",
      [chatId]
    );

    if (!rideCheck.length) {
      await connection.end();
      return res.status(404).json({ message: "Nie znaleziono przejazdu" });
    }

    const [result] = await connection.execute(
      "UPDATE przejazdy SET status_id = 5 WHERE id = ?",
      [chatId]
    );

    await connection.end();

    if (result.affectedRows === 0) {
      return res
        .status(500)
        .json({ message: "Nie udało się zaktualizować statusu przejazdu" });
    }

    res.status(200).json({ message: "Czat i przejazd zostały zamknięte" });
  } catch (err) {
    console.error("Error deleting chat:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "http://localhost:8100", methods: ["GET", "POST"] },
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
    // 1) Przytnij timestamp do formatu MySQL DATETIME
    const ts = new Date().toISOString().slice(0, 19).replace("T", " ");

    // 2) Pobierz imię nadawcy
    let senderName = "Nieznany";
    try {
      const connName = await connectDB();
      const [nameRows] = await connName.execute(
        "SELECT imie FROM uzytkownicy WHERE email = ?",
        [senderEmail]
      );
      await connName.end();
      if (nameRows.length) senderName = nameRows[0].imie;
    } catch (e) {
      console.error("Błąd pobierania imienia:", e);
    }

    // 3) Emituj do pozostałych w pokoju, podając też rideId i senderName
    socket.broadcast.to(`ride-${rideId}`).emit("receiveMessage", {
      rideId,
      senderEmail,
      senderName,
      message,
      timestamp: ts,
    });

    // 4) Zapisz w bazie w tle
    (async () => {
      try {
        const conn = await connectDB();

        // Pobierz pasazer_id i kierowca_id
        const [tripRows] = await conn.execute(
          "SELECT pasazer_id, kierowca_id FROM przejazdy WHERE id = ?",
          [rideId]
        );
        if (!tripRows.length) {
          await conn.end();
          return;
        }
        const { pasazer_id, kierowca_id } = tripRows[0];

        // Pobierz emaile obu stron
        const [pasRows] = await conn.execute(
          "SELECT email FROM uzytkownicy WHERE id = ?",
          [pasazer_id]
        );
        const [kierRows] = await conn.execute(
          "SELECT email FROM uzytkownicy WHERE id = ?",
          [kierowca_id]
        );
        const pasEmail = pasRows[0]?.email ?? null;
        const kierEmail = kierRows[0]?.email ?? null;

        // Wybierz odbiorcę
        const receiverEmail = senderEmail === pasEmail ? kierEmail : pasEmail;

        // Wstaw rekord
        await conn.execute(
          `INSERT INTO wiadomosci
           (nadawca_email, odbiorca_email, przejazd_id, tresc, czas)
         VALUES (?,             ?,               ?,           ?,    ?)`,
          [senderEmail, receiverEmail, rideId, message, ts]
        );

        await conn.end();
      } catch (err) {
        console.error("Błąd zapisu czatu:", err);
      }
    })();
  });
  socket.on("disconnect", () => {});
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
    if (!rows.length)
      return res.status(404).json({ message: "Nie znaleziono użytkownika" });
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

app.delete("/profile", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const connection = await connectDB();
    await connection.execute(
      "DELETE FROM rola_as_uzytkownik WHERE uzytkownik_id=?",
      [userId]
    );
    await connection.execute("DELETE FROM uzytkownicy WHERE id=?", [userId]);
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
    await connection.execute("UPDATE uzytkownicy SET haslo_hash=? WHERE id=?", [
      newPassword,
      userId,
    ]);
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
      if (typeof rideData.trasa_przejazdu === "string") {
        try {
          // Sprawdź, czy to możliwy JSON string
          if (
            rideData.trasa_przejazdu.startsWith("{") ||
            rideData.trasa_przejazdu.startsWith("[")
          ) {
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
          data_zakonczenia,
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
          rideId,
        ]);

        await connection.end();

        if (result.affectedRows === 0) {
          return res
            .status(404)
            .json({ message: "Przejazd nie został zaktualizowany" });
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
        closed_rides: Number(stats.closed_rides),
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
      const [rows] = await connection.execute(
        "SELECT * FROM statusy_przejazdu"
      );
      await connection.end();
      res.json(rows);
    } catch (err) {
      res.status(500).json({ message: "Błąd serwera" });
    }
  }
);
//--------------------------------------------------------------------------------------------------------------------- Koniec zmian ADMIN-Przeajdy

//--------------------------------------------------------------------------------------------------------------------- Poczatek zmian Zakończenie przejazdu

// Endpoint do dodawania oceny kierowcy i aktualizacji jego średniej oceny
app.post("/oceny", authenticateToken, async (req, res) => {
  const { iv, data } = req.body;
  if (!iv || !data) {
    return res.status(400).json({ message: "Brak danych" });
  }

  try {
    const decryptedData = decryptData(iv, data);
    const { kierowca_id, przejazd_id, ocena, komentarz } = decryptedData;
    const pasazer_id = req.user.id; // ID pasażera z tokena JWT

    if (!kierowca_id || !przejazd_id || !ocena) {
      return res.status(400).json({ message: "Brak wymaganych danych" });
    }

    const connection = await connectDB();

    try {
      // Rozpoczęcie transakcji
      await connection.beginTransaction();

      // 1. Dodaj ocenę kierowcy
      const query = `
        INSERT INTO oceny_kierowcow 
        (kierowca_id, pasazer_id, przejazd_id, ocena, komentarz, data_oceny)
        VALUES (?, ?, ?, ?, ?, NOW())
      `;

      await connection.execute(query, [
        kierowca_id,
        pasazer_id,
        przejazd_id,
        ocena,
        komentarz || null,
      ]);

      // 2. Aktualizuj średnią ocenę kierowcy
      await connection.execute("CALL UpdateDriverRating(?)", [kierowca_id]);

      // Zatwierdź transakcję
      await connection.commit();

      res
        .status(201)
        .json({
          message:
            "Ocena została zapisana i średnia ocena kierowcy zaktualizowana",
        });
    } catch (err) {
      // W przypadku błędu wycofaj transakcję
      await connection.rollback();
      throw err;
    } finally {
      await connection.end();
    }
  } catch (err) {
    console.error("Błąd zapisywania oceny:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

//--------------------------------------------------------------------------------------------------------------------- Koniec zmian Zakończenie przejazdu

// GET payments - can filter by ride ID or user ID
app.get("/platnosci", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { przejazd_id } = req.query;

    const connection = await connectDB();
    let query = `
      SELECT 
        p.id, 
        p.przejazd_id, 
        p.kwota, 
        p.data, 
        p.id_uzytkownika,
        u.imie AS nazwa_uzytkownika
      FROM platnosci p
      JOIN uzytkownicy u ON p.id_uzytkownika = u.id
    `;

    const params = [];

    // Only admins can see all payments, users see only their own
    if (req.user.roleId !== 1) {
      query += ` AND p.id_uzytkownika = ?`;
      params.push(userId);
    }

    query += ` ORDER BY p.data DESC`;

    const [rows] = await connection.execute(query, params);
    await connection.end();

    // Encrypt data before sending
    const encryptedData = await encryptData(rows);
    res.json(encryptedData);
  } catch (err) {
    console.error("Error fetching payments:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

// POST new payment
app.post("/platnosci", authenticateToken, async (req, res) => {
  try {
    const { iv, data } = req.body;

    if (!iv || !data) {
      return res.status(400).json({ message: "Brak danych" });
    }

    // Decrypt request data
    const decryptedData = decryptData(iv, data);
    const { przejazd_id, kwota } = decryptedData;
    const id_uzytkownika = req.user.id;
    console.log(przejazd_id, kwota);
    if (!przejazd_id || !kwota) {
      return res.status(400).json({ message: "Brak wymaganych danych" });
    }

    const connection = await connectDB();

    try {
      // Add payment
      const [result] = await connection.execute(
        "INSERT INTO platnosci (przejazd_id, kwota, data, id_uzytkownika) VALUES (?, ?, NOW(), ?)",
        [przejazd_id, kwota, id_uzytkownika]
      );

      await connection.end();

      res.status(201).json({
        message: "Płatność zapisana",
        id: result.insertId,
      });
    } catch (err) {
      await connection.end();
      throw err;
    }
  } catch (err) {
    console.error("Error processing payment:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

//--------------------------------------------------------------------------------------------------------------------- Początek zmian Ranking

// Endpoint dla rankingu kierowców
app.get("/api/ranking-kierowcow", async (req, res) => {
  try {
    const connection = await connectDB();
    const query = `
      SELECT 
        u.id,
        u.imie AS name,
        k.ocena AS averageRating,
        (SELECT COUNT(*) FROM oceny_kierowcow WHERE kierowca_id = u.id) AS totalReviews
      FROM uzytkownicy u
      JOIN kierowcy k ON u.id = k.uzytkownik_id
      JOIN rola_as_uzytkownik rau ON u.id = rau.uzytkownik_id
      WHERE rau.rola_id = 3 -- Rola kierowcy
      ORDER BY k.ocena DESC
    `;
    const [rows] = await connection.execute(query);
    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error("Błąd podczas pobierania rankingu kierowców:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

// Endpoint dla pobierania recenzji kierowcy
app.get("/api/reviews/:id", async (req, res) => {
  const driverId = req.params.id;
  try {
    const connection = await connectDB();
    const query = `
      SELECT 
        u.imie AS user,
        o.komentarz AS text,
        o.data_oceny AS date,
        o.ocena AS rating
      FROM oceny_kierowcow o
      JOIN uzytkownicy u ON o.pasazer_id = u.id
      WHERE o.kierowca_id = ?
      ORDER BY o.data_oceny DESC
    `;
    const [rows] = await connection.execute(query, [driverId]);
    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error("Błąd podczas pobierania recenzji kierowcy:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});
//--------------------------------------------------------------------------------------------------------------------- Koniec zmian Ranking

//--------------------------------------------------------------------------------------------------------------------- Początek zmian Ranking CRUD
// Pobierz wszystkich kierowców z informacjami o użytkownikach
app.get("/admin/drivers", authenticateToken, authorizeRole(1), async (req, res) => {
  try {
    const connection = await connectDB();
    const query = `
      SELECT 
        k.uzytkownik_id,
        u.imie,
        u.email,
        u.telefon,
        u.data_utworzenia,
        k.numer_prawa_jazdy,
        k.model_pojazdu,
        k.nr_rejestracyjny,
        k.kolor_pojazdu,
        k.ocena,
        (SELECT COUNT(*) FROM oceny_kierowcow WHERE kierowca_id = k.uzytkownik_id) as liczba_ocen,
        l.szerokosc_geo,
        l.dlugosc_geo,
        l.zaktualizowano
      FROM 
        kierowcy k
      JOIN 
        uzytkownicy u ON k.uzytkownik_id = u.id
      LEFT JOIN 
        lokalizacje l ON u.id = l.uzytkownik_id
      ORDER BY 
        u.data_utworzenia DESC
    `;
    const [rows] = await connection.execute(query);

    // Formatuj dane, aby zawierały lokalizację jako zagnieżdżony obiekt jeśli jest dostępna
    const formattedRows = rows.map(row => {
      const driver = { ...row };
      
      // Jeśli mamy dane lokalizacyjne, utwórz z nich zagnieżdżony obiekt
      if (row.szerokosc_geo !== null) {
        driver.ostatnia_lokalizacja = {
          szerokosc_geo: row.szerokosc_geo,
          dlugosc_geo: row.dlugosc_geo,
          zaktualizowano: row.zaktualizowano
        };
      }
      
      // Usuń surowe pola lokalizacji
      delete driver.szerokosc_geo;
      delete driver.dlugosc_geo;
      delete driver.zaktualizowano;
      
      return driver;
    });

    await connection.end();
    const encryptedData = await encryptData(formattedRows);
    res.json(encryptedData);
  } catch (err) {
    console.error("Błąd podczas pobierania kierowców:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

// Pobierz kwalifikujących się użytkowników, którzy mogą zostać kierowcami (tych z rolą kierowcy, którzy jeszcze nie są kierowcami)
app.get("/admin/eligible-drivers", authenticateToken, authorizeRole(1), async (req, res) => {
  try {
    const connection = await connectDB();
    const query = `
      SELECT 
        u.id, u.imie, u.email
      FROM 
        uzytkownicy u
      JOIN 
        rola_as_uzytkownik rau ON u.id = rau.uzytkownik_id
      WHERE 
        rau.rola_id = 3  -- ID roli kierowcy
        AND NOT EXISTS (
          SELECT 1 FROM kierowcy k WHERE k.uzytkownik_id = u.id
        )
      ORDER BY 
        u.imie, u.email
    `;
    const [rows] = await connection.execute(query);
    await connection.end();
    const encryptedData = await encryptData(rows);
    res.json(encryptedData);
  } catch (err) {
    console.error("Błąd podczas pobierania kwalifikujących się kierowców:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

// Pobierz dane konkretnego kierowcy
app.get("/admin/drivers/:id", authenticateToken, authorizeRole(1), async (req, res) => {
  try {
    const driverId = req.params.id;
    const connection = await connectDB();
    const query = `
      SELECT 
        k.*,
        u.imie,
        u.email,
        u.telefon,
        u.data_utworzenia
      FROM 
        kierowcy k
      JOIN 
        uzytkownicy u ON k.uzytkownik_id = u.id
      WHERE 
        k.uzytkownik_id = ?
    `;
    const [rows] = await connection.execute(query, [driverId]);
    
    if (rows.length === 0) {
      await connection.end();
      return res.status(404).json({ message: "Kierowca nie znaleziony" });
    }
    
    await connection.end();
    const encryptedData = await encryptData(rows[0]);
    res.json(encryptedData);
  } catch (err) {
    console.error("Błąd podczas pobierania danych kierowcy:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

// Pobierz recenzje konkretnego kierowcy
app.get("/admin/drivers/:id/reviews", authenticateToken, authorizeRole(1), async (req, res) => {
  try {
    const driverId = req.params.id;
    const connection = await connectDB();
    const query = `
      SELECT 
        o.id,
        o.kierowca_id,
        o.pasazer_id,
        o.przejazd_id,
        o.ocena,
        o.komentarz,
        o.data_oceny,
        u.imie as user_name,
        u.email as user_email
      FROM 
        oceny_kierowcow o
      JOIN 
        uzytkownicy u ON o.pasazer_id = u.id
      WHERE 
        o.kierowca_id = ?
      ORDER BY 
        o.data_oceny DESC
    `;
    const [rows] = await connection.execute(query, [driverId]);
    await connection.end();
    const encryptedData = await encryptData(rows);
    res.json(encryptedData);
  } catch (err) {
    console.error("Błąd podczas pobierania recenzji kierowcy:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

// Dodaj nowego kierowcę
app.post("/admin/drivers", authenticateToken, authorizeRole(1), async (req, res) => {
  try {
    const { iv, data } = req.body;
    const decryptedData = decryptData(iv, data);
    
    const {
      uzytkownik_id,
      numer_prawa_jazdy,
      model_pojazdu,
      nr_rejestracyjny,
      kolor_pojazdu
    } = decryptedData;
    
    if (!uzytkownik_id) {
      return res.status(400).json({ message: "Brak wymaganego ID użytkownika" });
    }
    
    const connection = await connectDB();
    
    // Sprawdź czy użytkownik istnieje i ma rolę kierowcy
    const [userCheck] = await connection.execute(`
      SELECT u.id FROM uzytkownicy u
      JOIN rola_as_uzytkownik r ON u.id = r.uzytkownik_id
      WHERE u.id = ? AND r.rola_id = 3
    `, [uzytkownik_id]);
    
    if (userCheck.length === 0) {
      await connection.end();
      return res.status(400).json({ message: "Użytkownik o podanym ID nie istnieje lub nie ma roli kierowcy" });
    }
    
    // Sprawdź czy rekord kierowcy już istnieje
    const [driverCheck] = await connection.execute(
      "SELECT uzytkownik_id FROM kierowcy WHERE uzytkownik_id = ?",
      [uzytkownik_id]
    );
    
    if (driverCheck.length > 0) {
      await connection.end();
      return res.status(400).json({ message: "Ten użytkownik ma już dane kierowcy" });
    }
    
    // Wstaw nowego kierowcę
    const query = `
      INSERT INTO kierowcy (
        uzytkownik_id,
        numer_prawa_jazdy,
        model_pojazdu,
        nr_rejestracyjny,
        kolor_pojazdu,
        ocena
      ) VALUES (?, ?, ?, ?, ?, 5.00)
    `;
    
    await connection.execute(query, [
      uzytkownik_id,
      numer_prawa_jazdy || null,
      model_pojazdu || null,
      nr_rejestracyjny || null,
      kolor_pojazdu || null
    ]);
    
    await connection.end();
    res.status(201).json({ message: "Kierowca dodany pomyślnie" });
  } catch (err) {
    console.error("Błąd podczas dodawania kierowcy:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

// Zaktualizuj dane kierowcy
app.put("/admin/drivers/:id", authenticateToken, authorizeRole(1), async (req, res) => {
  try {
    const driverId = req.params.id;
    const { iv, data } = req.body;
    const decryptedData = decryptData(iv, data);
    
    const {
      numer_prawa_jazdy,
      model_pojazdu,
      nr_rejestracyjny,
      kolor_pojazdu
    } = decryptedData;
    
    const connection = await connectDB();
    
    // Sprawdź czy kierowca istnieje
    const [driverCheck] = await connection.execute(
      "SELECT uzytkownik_id FROM kierowcy WHERE uzytkownik_id = ?",
      [driverId]
    );
    
    if (driverCheck.length === 0) {
      await connection.end();
      return res.status(404).json({ message: "Kierowca nie znaleziony" });
    }
    
    // Aktualizuj dane kierowcy
    const query = `
      UPDATE kierowcy SET
        numer_prawa_jazdy = ?,
        model_pojazdu = ?,
        nr_rejestracyjny = ?,
        kolor_pojazdu = ?
      WHERE uzytkownik_id = ?
    `;
    
    await connection.execute(query, [
      numer_prawa_jazdy,
      model_pojazdu,
      nr_rejestracyjny,
      kolor_pojazdu,
      driverId
    ]);
    
    await connection.end();
    res.json({ message: "Dane kierowcy zaktualizowane" });
  } catch (err) {
    console.error("Błąd podczas aktualizowania danych kierowcy:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

// Usuń kierowcę
app.delete("/admin/drivers/:id", authenticateToken, authorizeRole(1), async (req, res) => {
  try {
    const driverId = req.params.id;
    const connection = await connectDB();
    
    // Najpierw sprawdź czy kierowca istnieje
    const [driverCheck] = await connection.execute(
      "SELECT uzytkownik_id FROM kierowcy WHERE uzytkownik_id = ?",
      [driverId]
    );
    
    if (driverCheck.length === 0) {
      await connection.end();
      return res.status(404).json({ message: "Kierowca nie znaleziony" });
    }
    
    // Usuwamy tylko rekord kierowcy, nie konto użytkownika
    await connection.execute(
      "DELETE FROM kierowcy WHERE uzytkownik_id = ?", 
      [driverId]
    );
    
    await connection.end();
    res.json({ message: "Dane kierowcy zostały usunięte" });
  } catch (err) {
    console.error("Błąd podczas usuwania kierowcy:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});

// Usuń recenzję kierowcy
app.delete("/admin/reviews/:id", authenticateToken, authorizeRole(1), async (req, res) => {
  try {
    const reviewId = req.params.id;
    const connection = await connectDB();
    
    // Najpierw sprawdź czy recenzja istnieje
    const [reviewCheck] = await connection.execute(
      "SELECT id, kierowca_id FROM oceny_kierowcow WHERE id = ?",
      [reviewId]
    );
    
    if (reviewCheck.length === 0) {
      await connection.end();
      return res.status(404).json({ message: "Recenzja nie znaleziona" });
    }
    
    // Zapisz ID kierowcy przed usunięciem recenzji do późniejszej aktualizacji średniej oceny
    const kierowcaId = reviewCheck[0].kierowca_id;
    
    // Usuń recenzję
    await connection.execute(
      "DELETE FROM oceny_kierowcow WHERE id = ?", 
      [reviewId]
    );
    
    // Zaktualizuj średnią ocenę kierowcy
    await connection.execute("CALL UpdateDriverRating(?)", [kierowcaId]);
    
    await connection.end();
    res.json({ message: "Recenzja została usunięta" });
  } catch (err) {
    console.error("Błąd podczas usuwania recenzji:", err);
    res.status(500).json({ message: "Błąd serwera" });
  }
});
//--------------------------------------------------------------------------------------------------------------------- Koniec zmian Ranking CRUD
//--------------------------------------------------------------------------------------------------------------------- Początek zmian Odświeżanie tokenu
// Dodaj w endpoincie refresh-token
app.post("/refresh-token", authenticateToken, async (req, res) => {
  try {
    // Pobierz informacje o użytkowniku z tokenu
    const userId = req.user.id;
    const email = req.user.email;
    const roleId = req.user.roleId;
    
    //console.log(`[${new Date().toISOString()}] Odświeżanie tokenu dla użytkownika: ${email} (ID: ${userId})`);
    
    // Sprawdź, czy użytkownik nadal istnieje w bazie danych
    const connection = await connectDB();
    const [userRows] = await connection.execute(
      'SELECT * FROM uzytkownicy WHERE id = ?',
      [userId]
    );
    
    if (userRows.length === 0) {
      await connection.end();
      //console.log(`[${new Date().toISOString()}] Nieudane odświeżenie tokenu - użytkownik nie istnieje: ${email}`);
      return res.status(404).json({ message: "Użytkownik nie istnieje" });
    }
    
    // Wygeneruj nowy token
    const newToken = generateToken(email, roleId, userId);
    await connection.end();
    
    // Dekoduj nowy token aby poznać jego datę wygaśnięcia
    const decoded = jwt.verify(newToken, JWT_SECRET);
    const expirationTime = new Date(decoded.exp * 1000).toISOString();
    
    //console.log(`[${new Date().toISOString()}] Token odświeżony dla ${email}, wygaśnie: ${expirationTime}`);
    
    // Zwróć nowy token
    res.json({ 
      message: "Token został odświeżony",
      token: newToken 
    });
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Błąd podczas odświeżania tokenu:`, error);
    res.status(500).json({ message: "Wystąpił błąd serwera" });
  }
});
//--------------------------------------------------------------------------------------------------------------------- Koniec zmian Odświeżanie tokenu