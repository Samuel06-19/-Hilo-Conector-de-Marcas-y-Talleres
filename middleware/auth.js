import jwt from "jsonwebtoken";

export function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: "No autenticado. Iniciá sesión de nuevo." });
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { id, rol, nombre, organizacion, tallerId }
    next();
  } catch {
    return res.status(401).json({ error: "Sesión inválida o vencida. Iniciá sesión de nuevo." });
  }
}

export function requireRole(rol) {
  return (req, res, next) => {
    if (req.user.rol !== rol) {
      return res.status(403).json({ error: `Esta acción es solo para cuentas de tipo "${rol}".` });
    }
    next();
  };
}

export function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (!token || token !== process.env.ADMIN_TOKEN) {
    return res.status(403).json({ error: "Token de administrador inválido." });
  }
  next();
}
