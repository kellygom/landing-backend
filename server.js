import express from "express";
import cors from "cors";
import pg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from 'bcryptjs';
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import { z } from "zod";
import dotenv from "dotenv";

dotenv.config();

// Validación de entorno
if (!process.env.DATABASE_URL) {
  console.error("❌ Error: DATABASE_URL no definida");
  process.exit(1);
}

const { Pool } = pg;
const app = express();

// Seguridad y configuración
const JWT_CONFIG = {
  secret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
  expiresIn: '1h',
  algorithm: 'HS256'
};
const SALT_ROUNDS = 12;

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET || crypto.randomBytes(32).toString('hex')));
app.use(morgan('combined'));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Rate limit
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
app.use('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 5 }));

// DB
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Usuarios
const usuarios = [
  {
    username: "admin",
    passwordHash: bcrypt.hashSync("1234", SALT_ROUNDS)
  }
];

// Validación
const loginSchema = z.object({
  username: z.string().min(1).max(50),
  password: z.string().min(1).max(100)
});

// Rutas
app.get("/", (req, res) => {
  res.send("🚀 API funcionando correctamente");
});

// ✅ LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const parsed = loginSchema.safeParse({ username, password });
    if (!parsed.success) return res.status(400).json({ error: "Datos inválidos" });

    const usuario = usuarios.find((u) => u.username === username);
    if (!usuario || !bcrypt.compareSync(password, usuario.passwordHash)) {
      return res.status(401).json({ error: "Credenciales incorrectas" });
    }

    const token = jwt.sign({ username }, JWT_CONFIG.secret, {
      expiresIn: JWT_CONFIG.expiresIn,
      algorithm: JWT_CONFIG.algorithm,
    });

    res.json({ token });
  } catch (error) {
    console.error("❌ Error en login:", error);
    res.status(500).json({ error: "Error interno en login" });
  }
});

// ✅ Verificar token
const verificarToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1] || req.signedCookies.token;
  if (!token) return res.status(401).json({ error: "Acceso no autorizado" });

  jwt.verify(token, JWT_CONFIG.secret, { algorithms: [JWT_CONFIG.algorithm] }, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = { username: decoded.username };
    next();
  });
};

// ✅ Obtener pedidos
app.get("/api/pedidos", verificarToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *, 
      (SELECT COUNT(*) FROM pedidos) as total_count
      FROM pedidos 
      ORDER BY id DESC
      LIMIT 100
    `);
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// ✅ Insertar pedido (desde landing)
app.post("/api/pedidos", async (req, res) => {
  try {
    const {
      nombre, cedula, telefono, direccion,
      barrio, ciudad, departamento,
      modelo, color, talla, cantidad, precio
    } = req.body;

    const result = await pool.query(`
      INSERT INTO pedidos 
        (nombre, cedula, telefono, direccion, barrio, ciudad, departamento, modelo, color, talla, cantidad, precio)
      VALUES 
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      RETURNING *
    `, [nombre, cedula, telefono, direccion, barrio, ciudad, departamento, modelo, color, talla, cantidad, precio]);

    res.status(201).json({ success: true, pedido: result.rows[0] });
  } catch (error) {
    console.error("❌ Error al insertar pedido:", error);
    res.status(500).json({ error: "Error al procesar el pedido" });
  }
});

// Middleware de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Iniciar servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
});
