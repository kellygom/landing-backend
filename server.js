import express from "express";
import cors from "cors";
import pg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import { z } from "zod";
import dotenv from "dotenv";

// Configuración de variables de entorno
dotenv.config();

// Validación de variables críticas
if (!process.env.DATABASE_URL) {
  console.error("Error: DATABASE_URL no está definida en las variables de entorno");
  process.exit(1);
}

const { Pool } = pg;
const app = express();

// 1. Configuración Segura Mejorada
const JWT_CONFIG = {
  secret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
  expiresIn: '1h',
  algorithm: 'HS256'
};
const SALT_ROUNDS = 12;

// 2. Middlewares de Seguridad Mejorados
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

// Configuración de logs
app.use(morgan('combined'));

// Headers de seguridad adicionales
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// 3. Rate Limiting Mejorado
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Demasiadas solicitudes desde esta IP',
  skip: (req) => req.ip === '127.0.0.1' // Excluir localhost si es necesario
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Demasiados intentos de login desde esta IP'
});

app.use('/api/', apiLimiter);
app.use('/api/login', loginLimiter);

// 4. Conexión Segura a PostgreSQL (Manteniendo original)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { 
    rejectUnauthorized: true,
    ca: process.env.CA_CERT 
  } : false
});

// 5. Usuarios con Contraseñas Hasheadas (Manteniendo original)
const usuarios = [
  {
    username: "admin",
    passwordHash: bcrypt.hashSync("1234", SALT_ROUNDS) // Solo para desarrollo!
  }
];

// 6. Validación de Entrada Mejorada (Manteniendo lógica original)
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return '';
  return input.replace(/[^a-zA-Z0-9\sáéíóúÁÉÍÓÚñÑ@.,-]/g, '');
};

// Esquema de validación para login
const loginSchema = z.object({
  username: z.string().min(1).max(50),
  password: z.string().min(1).max(100)
});

// 7. Rutas Seguras (Manteniendo lógica original pero con validación)
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = loginSchema.parse(req.body);
    const sanitizedUsername = sanitizeInput(username);
    
    const usuario = usuarios.find(u => u.username === sanitizedUsername);
    if (!usuario || !await bcrypt.compare(password, usuario.passwordHash)) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    const token = jwt.sign(
      { 
        username: usuario.username,
        exp: Math.floor(Date.now() / 1000) + (60 * 60)
      }, 
      JWT_CONFIG.secret,
      { algorithm: JWT_CONFIG.algorithm }
    );

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000,
      signed: true
    };

    res.cookie('token', token, cookieOptions)
       .json({ success: true });
  } catch (error) {
    res.status(400).json({ error: "Datos de entrada inválidos" });
  }
});

// 8. Middleware de Autenticación (Manteniendo lógica original pero mejorado)
const verificarToken = (req, res, next) => {
  const token = req.signedCookies.token || req.headers['x-access-token'];
  
  if (!token) return res.status(401).json({ error: "Acceso no autorizado" });

  jwt.verify(token, JWT_CONFIG.secret, { algorithms: [JWT_CONFIG.algorithm] }, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = { username: decoded.username };
    next();
  });
};

// 9. Rutas Protegidas (Manteniendo lógica original)
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

// 10. Puerto Seguro (Manteniendo original)
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor seguro corriendo en puerto ${PORT}`);
});

// Middleware de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: process.env.NODE_ENV === 'development' ? err.message : 'Error interno del servidor' 
  });
});