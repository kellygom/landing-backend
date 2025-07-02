import express from "express";
import cors from "cors";
import pg from "pg";
import jwt from "jsonwebtoken"; // Asegúrate de instalar esto

const { Pool } = pg;
const app = express();
app.use(cors());
app.use(express.json());

// 🔐 Clave para firmar los tokens (cámbiala en producción)
const JWT_SECRET = "super_secreto_123";

// Usuarios de prueba
const usuarios = [{ username: "admin", password: "1234" }];

// Conexión PostgreSQL (Render)
const pool = new Pool({
  connectionString: 'postgresql://db_user:Vtv6BG1QNeyLKiGQPLvBJCmVtehAEosE@dpg-d1dh9h7fte5s73b5slu0-a/intermedio_vbb8',
  ssl: { rejectUnauthorized: false }
});

// Ruta de prueba
app.get("/", (req, res) => {
  res.send("✅ API funcionando correctamente!");
});

// Ruta de login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  console.log("📩 Datos recibidos en /login:", req.body);
  const usuario = usuarios.find(u => u.username === username && u.password === password);
  if (!usuario) return res.status(401).json({ error: "Credenciales inválidas" });

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ token }); // 🔴 Asegúrate de que esta línea exista
});


// Middleware para proteger rutas
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

// Ruta protegida: obtener pedidos
app.get("/api/pedidos", verificarToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM pedidos ORDER BY id DESC");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ mensaje: "Error al obtener los pedidos" });
  }
});

// Ruta protegida: actualizar estado
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
    res.status(500).json({ error: "Error al actualizar el estado" });
  }
});

// Ruta protegida: eliminar pedido
app.delete("/api/pedidos/:id", verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    await pool.query("DELETE FROM pedidos WHERE id = $1", [id]);
    res.json({ mensaje: "Pedido eliminado correctamente" });
  } catch (error) {
    res.status(500).json({ error: "Error al eliminar el pedido" });
  }
});

// Puerto
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
});
