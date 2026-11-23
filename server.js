// API RESTful de tareas: Express + fs.promises + JWT + bcryptjs
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs').promises; // asincrono: no bloquea el Event Loop
const path = require('path');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || 'clave-secreta-de-desarrollo'; // en produccion: variable de entorno
const TAREAS_FILE = path.join(__dirname, 'tareas.json');
const USUARIOS_FILE = path.join(__dirname, 'usuarios.json');

const app = express();
app.use(bodyParser.json()); // antes de las rutas

// Log de cada peticion (debugging con console.log)
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ---------- Utilidades de archivo (fs.promises) ----------
async function leer(file) {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return []; // archivo aun no existe
    if (err instanceof SyntaxError) throw httpError(500, `${path.basename(file)} esta corrupto (JSON mal formado)`);
    throw err;
  }
}
const escribir = (file, data) => fs.writeFile(file, JSON.stringify(data, null, 2));

// Serializa escrituras para evitar condiciones de carrera entre peticiones concurrentes
let cola = Promise.resolve();
const enCola = (fn) => (cola = cola.then(fn, fn));

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}
// Envuelve handlers async para que los errores lleguen al middleware de errores
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------- Middleware de autenticacion ----------
function auth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : header;
  if (!token) return next(httpError(401, 'Token requerido'));
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return next(httpError(403, err.name === 'TokenExpiredError' ? 'Token expirado' : 'Token invalido'));
    req.user = user;
    next();
  });
}

// ---------- Middleware de validacion ----------
function validarTarea(req, res, next) {
  const { titulo, descripcion } = req.body || {};
  const esTexto = (v) => typeof v === 'string' && v.trim() !== '';
  if (req.method === 'POST' && !(esTexto(titulo) && esTexto(descripcion)))
    return next(httpError(400, 'titulo y descripcion son obligatorios'));
  if (req.method === 'PUT' && titulo === undefined && descripcion === undefined)
    return next(httpError(400, 'Envia titulo y/o descripcion'));
  if ((titulo !== undefined && !esTexto(titulo)) || (descripcion !== undefined && !esTexto(descripcion)))
    return next(httpError(400, 'titulo y descripcion deben ser texto no vacio'));
  next();
}

function validarCredenciales(req, res, next) {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || !username.trim() || typeof password !== 'string' || password.length < 6)
    return next(httpError(400, 'username obligatorio y password de al menos 6 caracteres'));
  next();
}

// ---------- Rutas de autenticacion ----------
app.post('/register', validarCredenciales, wrap(async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await enCola(async () => {
    const usuarios = await leer(USUARIOS_FILE);
    if (usuarios.some((u) => u.username === username)) throw httpError(409, 'El usuario ya existe');
    usuarios.push({ id: Date.now(), username, password: hash });
    await escribir(USUARIOS_FILE, usuarios);
  });
  res.status(201).json({ mensaje: 'Usuario registrado' });
}));

app.post('/login', validarCredenciales, wrap(async (req, res) => {
  const { username, password } = req.body;
  const usuario = (await leer(USUARIOS_FILE)).find((u) => u.username === username);
  if (!usuario || !(await bcrypt.compare(password, usuario.password)))
    throw httpError(401, 'Credenciales incorrectas');
  const token = jwt.sign({ id: usuario.id, username }, SECRET, { expiresIn: '1h' });
  res.json({ token });
}));

// ---------- Rutas de tareas (protegidas) ----------
app.use('/tareas', auth);

app.get('/tareas', wrap(async (req, res) => {
  res.json(await leer(TAREAS_FILE));
}));

app.post('/tareas', validarTarea, wrap(async (req, res) => {
  const { titulo, descripcion } = req.body;
  const nueva = await enCola(async () => {
    const tareas = await leer(TAREAS_FILE);
    const t = { id: Math.max(0, ...tareas.map((x) => x.id)) + 1, titulo, descripcion };
    tareas.push(t);
    await escribir(TAREAS_FILE, tareas);
    return t;
  });
  res.status(201).json(nueva);
}));

app.put('/tareas/:id', validarTarea, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const { titulo, descripcion } = req.body;
  const t = await enCola(async () => {
    const tareas = await leer(TAREAS_FILE);
    const t = tareas.find((x) => x.id === id);
    if (!t) throw httpError(404, 'Tarea no encontrada');
    if (titulo !== undefined) t.titulo = titulo;
    if (descripcion !== undefined) t.descripcion = descripcion;
    await escribir(TAREAS_FILE, tareas);
    return t;
  });
  res.json(t);
}));

app.delete('/tareas/:id', wrap(async (req, res) => {
  const id = Number(req.params.id);
  await enCola(async () => {
    const tareas = await leer(TAREAS_FILE);
    const resto = tareas.filter((x) => x.id !== id);
    if (resto.length === tareas.length) throw httpError(404, 'Tarea no encontrada');
    await escribir(TAREAS_FILE, resto);
  });
  res.json({ mensaje: 'Tarea eliminada' });
}));

// ---------- 404 y manejo de errores (al final) ----------
app.use((req, res, next) => next(httpError(404, `Ruta no encontrada: ${req.method} ${req.url}`)));

app.use((err, req, res, next) => {
  // body-parser marca JSON invalido con err.status 400
  const status = err.status || 500;
  console.error(`[ERROR ${status}]`, err.stack);
  res.status(status).json({ error: status === 500 ? 'Error interno del servidor' : err.message });
});

app.listen(PORT, () => console.log(`Servidor iniciado en puerto ${PORT}`));
