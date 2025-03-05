import fs from 'fs';
import cors from 'cors';
import http from 'http';
import https from 'https';
import path from 'path';
import dotenv from 'dotenv';
import express from 'express';
import { fileURLToPath } from 'url';
import configureApp from './src/config/routes.js'
import db from "./src/config/db.js"


dotenv.config();

const APP_URL = process.env.APP_URL;
const PORT = process.env.PORT;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const app = express();
const server = http.createServer(app);


app.use('/', express.static(path.join(__dirname, 'src/uploads')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'src/views'));


configureApp(app);


app.get("/", (req, res) => {
  res.send("Study Buddy Runing ")
})

server.listen(PORT, () => {
  console.log(`Server is working on ${APP_URL}`);
});


// const sslOptions = {
//   ca: fs.readFileSync("/var/www/html/ssl/ca_bundle.crt"),
//   key: fs.readFileSync("/var/www/html/ssl/private.key"),
//   cert: fs.readFileSync("/var/www/html/ssl/certificate.crt"),
// };
// // Create HTTPS server
// const httpsServer = https.createServer(sslOptions, app);

// httpsServer.listen(PORT, () => {
//   console.log(`Server is working on ${APP_URL}`);
// })