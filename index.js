import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import { MercadoPagoConfig, Preference, Payment } from "mercadopago";
import { pool, query } from "./db.js";
import { requireAuth, requireRole, requireAdmin } from "./middleware/auth.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(cors());
app.use(express.json());

const mpClient = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN });
const COMISION_HILO = 0.10; // 10%, igual que en la demo original

function firmarToken(usuario) {
  return jwt.sign(
    {
      id: usuario.id,
      rol: usuario.rol,
      nombre: usuario.nombre,
      organizacion: usuario.organizacion,
      tallerId: usuario.taller_id || null,
    },
    process.env.JWT_SECRET,
    { expiresIn: "30d" }
  );
}

// ---------------------------------------------------------------------------
// AUTENTICACIÓN
// ---------------------------------------------------------------------------

app.post("/api/auth/register", async (req, res) => {
  try {
    const { nombre, email, password, rol, organizacion } = req.body;
    if (!nombre?.trim() || !email?.trim() || !password || !organizacion?.trim()) {
      return res.status(400).json({ error: "Faltan datos obligatorios." });
    }
    if (!["empresa", "taller"].includes(rol)) {
      return res.status(400).json({ error: "El rol debe ser 'empresa' o 'taller'." });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "La contraseña debe tener al menos 8 caracteres." });
    }

    const existente = await query("SELECT id FROM usuarios WHERE email = $1", [email.toLowerCase()]);
    if (existente.rows.length > 0) {
      return res.status(409).json({ error: "Ya existe una cuenta con ese email." });
    }

    const hash = await bcrypt.hash(password, 10);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const usuarioResult = await client.query(
        `INSERT INTO usuarios (nombre, email, password_hash, rol, organizacion)
         VALUES ($1, $2, $3, $4, $5) RETURNING id, nombre, email, rol, organizacion`,
        [nombre.trim(), email.toLowerCase().trim(), hash, rol, organizacion.trim()]
      );
      const usuario = usuarioResult.rows[0];

      let tallerId = null;
      if (rol === "taller") {
        const tallerResult = await client.query(
          `INSERT INTO talleres (usuario_id, nombre) VALUES ($1, $2) RETURNING id`,
          [usuario.id, organizacion.trim()]
        );
        tallerId = tallerResult.rows[0].id;
      }
      await client.query("COMMIT");

      const token = firmarToken({ ...usuario, taller_id: tallerId });
      res.status(201).json({ token, usuario: { ...usuario, tallerId } });
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "No se pudo crear la cuenta." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Ingresá email y contraseña." });
    }
    const result = await query(
      `SELECT u.*, t.id AS taller_id FROM usuarios u
       LEFT JOIN talleres t ON t.usuario_id = u.id
       WHERE u.email = $1`,
      [email.toLowerCase().trim()]
    );
    const usuario = result.rows[0];
    if (!usuario) {
      return res.status(401).json({ error: "Email o contraseña incorrectos." });
    }
    const ok = await bcrypt.compare(password, usuario.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Email o contraseña incorrectos." });
    }
    const token = firmarToken(usuario);
    res.json({
      token,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        rol: usuario.rol,
        organizacion: usuario.organizacion,
        tallerId: usuario.taller_id,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "No se pudo iniciar sesión." });
  }
});

// ---------------------------------------------------------------------------
// TALLERES
// ---------------------------------------------------------------------------

app.get("/api/talleres", async (_req, res) => {
  const result = await query(`
    SELECT t.id, t.nombre, t.especialidad, t.ubicacion, t.capacidad, t.verificado,
           COALESCE(AVG(r.estrellas), 0)::float AS rating,
           COUNT(r.id)::int AS cantidad_resenas
    FROM talleres t
    LEFT JOIN resenas r ON r.taller_id = t.id
    GROUP BY t.id
    ORDER BY t.creado_en DESC
  `);
  res.json(result.rows);
});

app.get("/api/talleres/:id", async (req, res) => {
  const tallerResult = await query(
    `SELECT t.id, t.nombre, t.especialidad, t.ubicacion, t.capacidad, t.verificado,
            COALESCE(AVG(r.estrellas), 0)::float AS rating
     FROM talleres t LEFT JOIN resenas r ON r.taller_id = t.id
     WHERE t.id = $1 GROUP BY t.id`,
    [req.params.id]
  );
  if (tallerResult.rows.length === 0) return res.status(404).json({ error: "Taller no encontrado." });
  const resenas = await query(
    "SELECT empresa_nombre, estrellas, comentario FROM resenas WHERE taller_id = $1 ORDER BY creado_en DESC",
    [req.params.id]
  );
  res.json({ ...tallerResult.rows[0], resenas: resenas.rows });
});

app.patch("/api/talleres/me", requireAuth, requireRole("taller"), async (req, res) => {
  const { especialidad, ubicacion, capacidad } = req.body;
  const result = await query(
    `UPDATE talleres SET
       especialidad = COALESCE($1, especialidad),
       ubicacion = COALESCE($2, ubicacion),
       capacidad = COALESCE($3, capacidad)
     WHERE usuario_id = $4 RETURNING *`,
    [especialidad, ubicacion, capacidad, req.user.id]
  );
  res.json(result.rows[0]);
});

// Un taller pide revisión manual en vez de auto-verificarse (más real: lo aprueba Hilo).
app.post("/api/talleres/me/solicitar-verificacion", requireAuth, requireRole("taller"), async (req, res) => {
  await query(
    "UPDATE talleres SET verificacion_pendiente = true WHERE usuario_id = $1",
    [req.user.id]
  );
  res.json({ ok: true });
});

// Ruta de administración: la usás vos mismo (con tu ADMIN_TOKEN) para aprobar talleres.
app.post("/api/admin/talleres/:id/verificar", requireAdmin, async (req, res) => {
  await query(
    "UPDATE talleres SET verificado = true, verificacion_pendiente = false WHERE id = $1",
    [req.params.id]
  );
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// PEDIDOS
// ---------------------------------------------------------------------------

app.get("/api/pedidos", requireAuth, async (req, res) => {
  const result =
    req.user.rol === "empresa"
      ? await query(
          `SELECT p.*, t.nombre AS taller_nombre FROM pedidos p
           JOIN talleres t ON t.id = p.taller_id
           WHERE p.empresa_id = $1 ORDER BY p.creado_en DESC`,
          [req.user.id]
        )
      : await query(
          `SELECT p.*, u.organizacion AS empresa_nombre FROM pedidos p
           JOIN usuarios u ON u.id = p.empresa_id
           WHERE p.taller_id = $1 ORDER BY p.creado_en DESC`,
          [req.user.tallerId]
        );
  res.json(result.rows);
});

app.post("/api/pedidos", requireAuth, requireRole("empresa"), async (req, res) => {
  const { tallerId, prenda, cantidad, descripcion, monto } = req.body;
  const cantidadNum = Number(cantidad);
  const montoNum = Number(monto);
  if (!tallerId || !prenda?.trim() || !cantidadNum || cantidadNum <= 0 || !montoNum || montoNum <= 0) {
    return res.status(400).json({ error: "Revisá los datos del pedido: faltan campos o son inválidos." });
  }
  const result = await query(
    `INSERT INTO pedidos (empresa_id, taller_id, prenda, cantidad, descripcion, monto)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
    [req.user.id, tallerId, prenda.trim(), cantidadNum, (descripcion || "").trim(), montoNum]
  );
  res.status(201).json(result.rows[0]);
});

const TRANSICIONES_TALLER = {
  Pendiente: ["Aceptado", "Rechazado"],
  Aceptado: ["En proceso"],
  "En proceso": ["Completado"],
};

app.patch("/api/pedidos/:id/estado", requireAuth, requireRole("taller"), async (req, res) => {
  const { estado } = req.body;
  const pedidoResult = await query("SELECT * FROM pedidos WHERE id = $1 AND taller_id = $2", [
    req.params.id,
    req.user.tallerId,
  ]);
  const pedido = pedidoResult.rows[0];
  if (!pedido) return res.status(404).json({ error: "Pedido no encontrado." });

  const permitidos = TRANSICIONES_TALLER[pedido.estado] || [];
  if (!permitidos.includes(estado)) {
    return res.status(400).json({ error: `No se puede pasar de "${pedido.estado}" a "${estado}".` });
  }
  const result = await query("UPDATE pedidos SET estado = $1 WHERE id = $2 RETURNING *", [estado, pedido.id]);
  res.json(result.rows[0]);
});

app.get("/api/pedidos/:id/mensajes", requireAuth, async (req, res) => {
  const acceso = await verificarAccesoPedido(req.params.id, req.user);
  if (!acceso) return res.status(403).json({ error: "No tenés acceso a este pedido." });
  const result = await query(
    "SELECT autor_nombre, autor_rol, texto, creado_en FROM mensajes WHERE pedido_id = $1 ORDER BY creado_en ASC",
    [req.params.id]
  );
  res.json(result.rows);
});

app.post("/api/pedidos/:id/mensajes", requireAuth, async (req, res) => {
  const acceso = await verificarAccesoPedido(req.params.id, req.user);
  if (!acceso) return res.status(403).json({ error: "No tenés acceso a este pedido." });
  const texto = (req.body.texto || "").trim();
  if (!texto) return res.status(400).json({ error: "El mensaje no puede estar vacío." });
  const result = await query(
    `INSERT INTO mensajes (pedido_id, autor_id, autor_nombre, autor_rol, texto)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [req.params.id, req.user.id, req.user.nombre, req.user.rol, texto]
  );
  res.status(201).json(result.rows[0]);
});

async function verificarAccesoPedido(pedidoId, user) {
  const result = await query("SELECT empresa_id, taller_id FROM pedidos WHERE id = $1", [pedidoId]);
  const pedido = result.rows[0];
  if (!pedido) return false;
  if (user.rol === "empresa") return pedido.empresa_id === user.id;
  return pedido.taller_id === user.tallerId;
}

// ---------------------------------------------------------------------------
// PAGOS REALES CON MERCADO PAGO (Checkout Pro)
// ---------------------------------------------------------------------------

app.post("/api/pedidos/:id/pagar", requireAuth, requireRole("empresa"), async (req, res) => {
  try {
    const result = await query(
      "SELECT * FROM pedidos WHERE id = $1 AND empresa_id = $2",
      [req.params.id, req.user.id]
    );
    const pedido = result.rows[0];
    if (!pedido) return res.status(404).json({ error: "Pedido no encontrado." });
    if (pedido.estado !== "Completado") {
      return res.status(400).json({ error: "Solo se puede pagar un pedido ya Completado por el taller." });
    }
    if (pedido.pagado) return res.status(400).json({ error: "Este pedido ya fue pagado." });

    const preference = new Preference(mpClient);
    const respuesta = await preference.create({
      body: {
        items: [
          {
            id: String(pedido.id),
            title: `Pedido #${pedido.id} - ${pedido.prenda}`,
            quantity: 1,
            currency_id: "ARS",
            unit_price: Number(pedido.monto),
          },
        ],
        external_reference: String(pedido.id),
        back_urls: {
          success: `${process.env.FRONTEND_URL}/?pago=exito&pedido=${pedido.id}`,
          failure: `${process.env.FRONTEND_URL}/?pago=error&pedido=${pedido.id}`,
          pending: `${process.env.FRONTEND_URL}/?pago=pendiente&pedido=${pedido.id}`,
        },
        auto_return: "approved",
        notification_url: `${process.env.BACKEND_URL}/api/webhooks/mercadopago`,
      },
    });

    await query("UPDATE pedidos SET mp_preference_id = $1 WHERE id = $2", [respuesta.id, pedido.id]);
    res.json({ init_point: respuesta.init_point });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "No se pudo iniciar el pago con Mercado Pago." });
  }
});

// Mercado Pago llama a esta URL automáticamente cuando cambia el estado de un pago.
app.post("/api/webhooks/mercadopago", async (req, res) => {
  try {
    const paymentId = req.body?.data?.id || req.query["data.id"];
    if (!paymentId) return res.sendStatus(200);

    const payment = new Payment(mpClient);
    const info = await payment.get({ id: paymentId });

    if (info.status === "approved") {
      const pedidoId = info.external_reference;
      await query(
        "UPDATE pedidos SET pagado = true, estado = 'Pagado', mp_payment_id = $1 WHERE id = $2",
        [String(paymentId), pedidoId]
      );
    }
    res.sendStatus(200);
  } catch (err) {
    console.error("Error procesando webhook de Mercado Pago:", err);
    res.sendStatus(200); // Igual respondemos 200 para que Mercado Pago no reintente indefinidamente.
  }
});

// El frontend usa esto para refrescar el estado de un pedido cuando el usuario vuelve del pago.
app.get("/api/pedidos/:id", requireAuth, async (req, res) => {
  const acceso = await verificarAccesoPedido(req.params.id, req.user);
  if (!acceso) return res.status(403).json({ error: "No tenés acceso a este pedido." });
  const result = await query("SELECT * FROM pedidos WHERE id = $1", [req.params.id]);
  res.json(result.rows[0]);
});

// ---------------------------------------------------------------------------
// CALIFICACIONES
// ---------------------------------------------------------------------------

app.post("/api/pedidos/:id/calificar", requireAuth, requireRole("empresa"), async (req, res) => {
  const { estrellas, comentario } = req.body;
  const estrellasNum = Number(estrellas);
  if (!estrellasNum || estrellasNum < 1 || estrellasNum > 5) {
    return res.status(400).json({ error: "La calificación debe ser entre 1 y 5 estrellas." });
  }
  const result = await query(
    "SELECT * FROM pedidos WHERE id = $1 AND empresa_id = $2",
    [req.params.id, req.user.id]
  );
  const pedido = result.rows[0];
  if (!pedido) return res.status(404).json({ error: "Pedido no encontrado." });
  if (!pedido.pagado) return res.status(400).json({ error: "Solo se puede calificar un pedido ya pagado." });
  if (pedido.calificado) return res.status(400).json({ error: "Este pedido ya fue calificado." });

  await query(
    "INSERT INTO resenas (taller_id, empresa_nombre, estrellas, comentario) VALUES ($1, $2, $3, $4)",
    [pedido.taller_id, req.user.organizacion, estrellasNum, (comentario || "").trim()]
  );
  await query("UPDATE pedidos SET calificado = true WHERE id = $1", [pedido.id]);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Servir el frontend (para poder desplegar todo junto en un solo servicio)
// ---------------------------------------------------------------------------

app.use(express.static(path.join(__dirname, "../frontend")));
app.get("*", (req, res) => {
  if (req.path.startsWith("/api")) return res.status(404).json({ error: "No encontrado." });
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Hilo backend corriendo en el puerto ${PORT}`));
