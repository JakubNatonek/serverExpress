const { DataTypes } = require('sequelize');
const sequelize = require('./Config');
const User = require('./User');

const Payment = sequelize.define('payment', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  przejazd_id: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  kwota: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false
  },
  data: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  id_uzytkownika: {
    type: DataTypes.INTEGER,
    allowNull: false
  }
}, {
  tableName: 'platnosci',
  timestamps: false
});

// Define relationships
Payment.belongsTo(User, { foreignKey: 'id_uzytkownika', as: 'uzytkownik' });
User.hasMany(Payment, { foreignKey: 'id_uzytkownika', as: 'platnosci' });

module.exports = Payment;