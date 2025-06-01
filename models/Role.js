const { DataTypes } = require('sequelize');
const sequelize = require('./Config');

const Role = sequelize.define('Role', {
  ID: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  przywilej: {
    type: DataTypes.STRING,
    allowNull: false
  }
}, {
  tableName: 'role',
  timestamps: false
});

module.exports = Role;