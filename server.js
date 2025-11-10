// server.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const app = express();
app.use(express.json());

// --- Helpers JWT
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ACCESS_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY;
const REFRESH_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY;

function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    ACCESS_SECRET,
    { expiresIn: ACCESS_EXPIRY }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    REFRESH_SECRET,
    { expiresIn: REFRESH_EXPIRY }
  );
}

// --- Middleware: Verificar token de acceso
function authenticateToken(req, res, next) {
  const header = req.headers['authorization'];
  const token = header && header.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token requerido' });

  jwt.verify(token, ACCESS_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido o expirado' });
    req.user = user;
    next();
  });
}
//Rutas
//Registro de usuario
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Se requiere usuario y contraseña' });

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length > 0)
      return res.status(409).json({ message: 'El usuario ya existe' });

    const hashed = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hashed]);
    res.status(201).json({ message: 'Usuario registrado correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al registrar usuario' });
  }
});
// Login de usuario
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Usuario y contraseña requeridos' });

  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) return res.status(401).json({ message: 'Credenciales inválidas' });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ message: 'Credenciales inválidas' });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    await pool.query('INSERT INTO refresh_tokens (user_id, token) VALUES (?, ?)', [user.id, refreshToken]);

    res.json({ accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al iniciar sesión' });
  }
});

// Ruta protegida
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: `Bienvenido, ${req.user.username}`, user: req.user });
});

// Refresh Token
app.post('/token', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ message: 'Refresh token requerido' });

  try {
    const [rows] = await pool.query('SELECT * FROM refresh_tokens WHERE token = ?', [refreshToken]);
    if (rows.length === 0) return res.status(403).json({ message: 'Refresh token inválido' });

    jwt.verify(refreshToken, REFRESH_SECRET, (err, user) => {
      if (err) return res.status(403).json({ message: 'Token expirado o inválido' });
      const newAccessToken = generateAccessToken(user);
      res.json({ accessToken: newAccessToken });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al refrescar token' });
  }
});

// Logout
app.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ message: 'Refresh token requerido' });

  try {
    await pool.query('DELETE FROM refresh_tokens WHERE token = ?', [refreshToken]);
    res.json({ message: 'Sesión cerrada correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al cerrar sesión' });
  }
});

// Iniciar servidor
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
