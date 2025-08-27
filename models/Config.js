const { Sequelize } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: 'mysql',
    logging: false // ustaw na console.log jeśli chcesz zobaczyć zapytania SQL
  }
);

// Testowanie połączenia
const testConnection = async () => {
  try {
    await sequelize.authenticate();
    console.log('Połączenie z bazą danych nawiązane pomyślnie.');
  } catch (error) {
    console.error('Błąd połączenia z bazą danych:', error);
  }
};

testConnection();

module.exports = sequelize;