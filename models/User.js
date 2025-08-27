const { DataTypes } = require('sequelize');
const sequelize = require('./Config');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  imie: {
    type: DataTypes.STRING,
    allowNull: true
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  telefon: {
    type: DataTypes.STRING,
    allowNull: true
  },
  haslo_hash: {
    type: DataTypes.STRING,
    allowNull: false
  },
  // Usunięto pole typ_uzytkownika, które nie istnieje w tabeli
  data_utworzenia: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  }
}, {
  tableName: 'uzytkownicy',
  timestamps: false
});

module.exports = User;