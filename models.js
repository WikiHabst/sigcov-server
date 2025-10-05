// models.js
const { Sequelize, DataTypes } = require('sequelize');
const credentials = require('./credentials.json');

const sequelize = credentials.env === 'dev' ? new Sequelize('sqlite::memory:') : new Sequelize(credentials.dbname, credentials.dbuser, credentials.dbpass, {
  host: 'tools.db.svc.wikimedia.cloud',
  dialect: 'mariadb',
});

const User = sequelize.define('User', {
  sub: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false,
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false
  },
  profile: {
    type: DataTypes.JSON
  },
  score: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
  }
}, {
  timestamps: true
});

const OAuthToken = sequelize.define('OAuthToken', {
  accessToken: { type: DataTypes.TEXT, allowNull: false },
  refreshToken: { type: DataTypes.TEXT },
  scope: { type: DataTypes.STRING },
  tokenType: { type: DataTypes.STRING },
  expiresAt: { type: DataTypes.DATE } // optional
}, {
  timestamps: true
});

User.hasMany(OAuthToken, { as: 'tokens' });
OAuthToken.belongsTo(User);

async function init({ force = false } = {}) {
  await sequelize.authenticate();
  await sequelize.sync({ force });
  console.log('DB synced');
}

module.exports = { sequelize, User, OAuthToken, init };
