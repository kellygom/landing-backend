import express from "express";
import cors from "cors";
import pg from "pg";

const { Pool } = pg;

const app = express();
app.use(cors());
app.use(express.json());

// Cambia esta URL por la que Render te da para tu base de datos
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.get("/", (req, res) => {
  res.send("API funcionando correctamente!");
});

app.post("/api/pedidos", async (req, res) => {
  const { nombre, telefono, direccion, producto } = req.body;

  try {
    await pool.query(
      "INSERT INTO pedidos (nombre, telefono, direccion, modelo, color, talla, cantidad) VALUES ($1, $2, $3, $4, $5, $6, $7)",
      [nombre, telefono, direccion, producto.modelo, producto.color, producto.talla, producto.cantidad]
    );
    res.json({ mensaje: "Pedido guardado correctamente" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ mensaje: "Error al guardar el pedido" });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
