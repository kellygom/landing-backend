import express from "express";
import cors from "cors";
import pg from "pg";

const { Pool } = pg;
const app = express();

app.use(cors());
app.use(express.json());

// Conexión a PostgreSQL
const pool = new Pool({
  connectionString: "postgresql://db_user:Vtv6BG1QNeyLKiGQPLvBJCmVtehAEosE@dpg-d1dh9h7fte5s73b5slu0-a/intermedio_vbb8",
  ssl: { rejectUnauthorized: false },
});

// Ruta prueba
app.get("/", (req, res) => {
  res.send("✅ API funcionando correctamente!");
});

// Obtener pedidos
app.get("/api/pedidos", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM pedidos ORDER BY id DESC");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ mensaje: "Error al obtener los pedidos" });
  }
});

// ✅ ACTUALIZAR estado de pedido
app.put("/api/pedidos/:id/estado", async (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;

  console.log("➡️ Actualizando pedido", id, "a estado:", estado);

  try {
    const result = await pool.query(
      "UPDATE pedidos SET estado = $1 WHERE id = $2 RETURNING *",
      [estado, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Pedido no encontrado" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error("❌ Error actualizando estado:", error);
    res.status(500).json({ error: "Error al actualizar el estado" });
  }
});

// Puerto
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
});
