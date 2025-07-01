import express from "express";
import cors from "cors";
import pg from "pg";

const { Pool } = pg;

const app = express();
app.use(cors());
app.use(express.json());

// Conexión a PostgreSQL en Render
const pool = new Pool({
  connectionString: 'postgresql://db_user:Vtv6BG1QNeyLKiGQPLvBJCmVtehAEosE@dpg-d1dh9h7fte5s73b5slu0-a/intermedio_vbb8',
  ssl: { rejectUnauthorized: false }
});


// Ruta de prueba
app.get("/", (req, res) => {
  res.send("✅ API funcionando correctamente!");
});

// Ruta para guardar pedidos
app.post("/api/pedidos", async (req, res) => {
  const {
    nombre,
    cedula,
    telefono,
    direccion,
    barrio,
    ciudad,
    departamento,
    producto
  } = req.body;

  try {
    // Calcula precio con descuento si hay 2 pares
    const precio =
      producto.cantidad === 2 ? 160000 : producto.cantidad * 90000;

    const query = `
      INSERT INTO pedidos 
        (nombre, cedula, telefono, direccion, barrio, ciudad, departamento, modelo, color, talla, cantidad, precio)
      VALUES 
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *;
    `;

    const values = [
      nombre,
      cedula,
      telefono,
      direccion,
      barrio,
      ciudad,
      departamento,
      producto.modelo,
      producto.color,
      producto.talla,
      producto.cantidad,
      precio
    ];

    const result = await pool.query(query, values);
    res.status(201).json({
      mensaje: "✅ Pedido guardado correctamente",
      pedido: result.rows[0]
    });
  } catch (error) {
    console.error("❌ Error al guardar el pedido:", error);
    res.status(500).json({ mensaje: "Error al guardar el pedido" });
  }
});

// Puerto para Render o local
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
});
// En el backend
app.get("/api/pedidos", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM pedidos ORDER BY id DESC");
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ mensaje: "Error al obtener los pedidos" });
  }
});

