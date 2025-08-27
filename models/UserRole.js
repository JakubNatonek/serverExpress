const { DataTypes } = require('sequelize');
const sequelize = require('./Config');
const User = require('./User');
const Role = require('./Role');

const UserRole = sequelize.define('UserRole', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  uzytkownik_id: {
    type: DataTypes.INTEGER,
    references: {
      model: User,
      key: 'id'
    }
  },
  rola_id: {
    type: DataTypes.INTEGER,
    references: {
      model: Role,
      key: 'ID'
    }
  }
}, {
  tableName: 'rola_as_uzytkownik',
  timestamps: false
});

// Definiujemy relacje
User.belongsToMany(Role, { through: UserRole, foreignKey: 'uzytkownik_id', otherKey: 'rola_id' });
Role.belongsToMany(User, { through: UserRole, foreignKey: 'rola_id', otherKey: 'uzytkownik_id' });

module.exports = UserRole;