import mysql from 'mysql2';
import util from 'util';
import Msg from '../utils/message.js';
import dotenv from 'dotenv';
dotenv.config();

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  database: process.env.DB_DATABASE,
};

let connection;

function handleDisconnect() {
  connection = mysql.createConnection(dbConfig);

  connection.connect((err) => {
    if (err) {
      console.log(Msg.dbConnectionError, err);
      setTimeout(handleDisconnect, 2000);
    } else {
      console.log(Msg.dbConnectionSuccess);
    }
  });

  connection.on('error', (err) => {
    console.error(Msg.dbError, err);
    if (err.code === Msg.protocolConnectionLost) {
      handleDisconnect();
    } else {
      throw err;
    }
  });
}

handleDisconnect();

function makeDb() {
  return {
    async query(sql, args) {
      return util.promisify(connection.query).call(connection, sql, args);
    },
    async close() {
      console.log(Msg.dbConnectionClosing);
      return util.promisify(connection.end).call(connection);
    }
  };
}
const db = makeDb();

export default db;
