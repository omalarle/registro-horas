const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

app.use(cors());
app.use(express.json());

// Simulación de base de datos en memoria
const users = []; // Aquí se almacenan los usuarios
const entries = []; // Aquí se almacenan las entradas

// Clave secreta para JWT
const SECRET_KEY = 'tu_clave_secreta';

// Ruta para registrar un nuevo usuario
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  res.send({ success: true });
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.send({ success: true, token });
  } else {
    res.status(401).send({ success: false, message: 'Credenciales incorrectas' });
  }
});

// Middleware para verificar el token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send({ message: 'Token no proporcionado' });
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(500).send({ message: 'Error al autenticar el token' });
    req.user = decoded;
    next();
  });
};

// Ruta para registrar una entrada o salida (protegida)
app.post('/entry', verifyToken, (req, res) => {
  const now = new Date().toLocaleString();
  entries.push({ user: req.user.username, time: now });
  res.send({ success: true, entries });
});

// Ruta para obtener las entradas (protegida)
app.get('/entries', verifyToken, (req, res) => {
  const userEntries = entries.filter(entry => entry.user === req.user.username);
  res.send(userEntries);
});

const PORT = 5000;
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));
