const { DataTypes } = require('sequelize');
const sequelize = require('./Config');
const User = require('./user');

const Lokalizacja = sequelize.define('lokalizacja', {
  uzytkownik_id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    references: {
      model: User,
      key: 'id'
    }
  },
  szerokosc_geo: {
    type: DataTypes.FLOAT,
    allowNull: false
  },
  dlugosc_geo: {
    type: DataTypes.FLOAT,
    allowNull: false
  },
  zaktualizowano: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  }
}, {
  tableName: 'lokalizacje',
  timestamps: false
});

// Establish relationship with User model
Lokalizacja.belongsTo(User, { foreignKey: 'uzytkownik_id' });
User.hasOne(Lokalizacja, { foreignKey: 'uzytkownik_id' });

module.exports = Lokalizacja;