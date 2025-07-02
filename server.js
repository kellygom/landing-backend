import express from "express";
import cors from "cors";
import pg from "pg";
import jwt from "jsonwebtoken";

const { Pool } = pg;
const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = "super_secreto_123";

const usuarios = [{ username: "admin", password: "1234" }];

const pool = new Pool({
  connectionString:
    "postgresql://db_user:Vtv6BG1QNeyLKiGQPLvBJCmVtehAEosE@dpg-d1dh9h7fte5s73b5slu0-a/intermedio_vbb8",
  ssl: { rejectUnauthorized: false },
});

// Ruta raíz
app.get("/", (req, res) => {
  res.send("✅ API funcionando correctamente!");
});

// Login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const usuario = usuarios.find(
    (u) => u.username === username && u.password === password
  );
  if (!usuario) return res.status(401).json({ error: "Credenciales inválidas" });

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ token });
});

// Middleware para verificar token
function verificarToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token requerido" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = user;
    next();
  });
}

// Obtener todos los pedidos (protegido)
app.get("/api/pedidos", verificarToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM pedidos ORDER BY id DESC");
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ mensaje: "Error al obtener los pedidos" });
  }
});

// Actualizar estado de pedido (protegido)
app.put("/api/pedidos/:id/estado", verificarToken, async (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;

  try {
    const result = await pool.query(
      "UPDATE pedidos SET estado = $1 WHERE id = $2 RETURNING *",
      [estado, id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al actualizar el estado" });
  }
});

// Eliminar pedido (protegido)
app.delete("/api/pedidos/:id", verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query("DELETE FROM pedidos WHERE id = $1", [id]);
    res.json({ mensaje: "Pedido eliminado correctamente" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error al eliminar el pedido" });
  }
});

// Crear nuevo pedido (puedes quitar 'verificarToken' si quieres permitir sin login)
app.post("/api/pedidos", async (req, res) => {
  const {
    nombre,
    cedula,
    telefono,
    direccion,
    barrio,
    ciudad,
    departamento,
    producto,
  } = req.body;

  if (
    !nombre ||
    !cedula ||
    !telefono ||
    !producto ||
    !producto.modelo ||
    !producto.color ||
    !producto.talla ||
    !producto.cantidad ||
    !producto.precio
  ) {
    return res.status(400).json({ error: "Faltan datos requeridos" });
  }

  const { modelo, color, talla, cantidad, precio } = producto;

  try {
    const result = await pool.query(
      `INSERT INTO pedidos
      (nombre, cedula, telefono, direccion, barrio, ciudad, departamento, modelo, color, talla, cantidad, precio, estado)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, 'pendiente') RETURNING *`,
      [
        nombre,
        cedula,
        telefono,
        direccion,
        barrio,
        ciudad,
        departamento,
        modelo,
        color,
        talla,
        cantidad,
        precio,
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Error insertando pedido:", error);
    res.status(500).json({ error: "Error al crear el pedido" });
  }
});

// Puerto
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
});
