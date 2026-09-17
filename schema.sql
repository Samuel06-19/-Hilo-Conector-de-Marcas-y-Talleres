-- Esquema de base de datos de Hilo (PostgreSQL)
-- Ejecutar una sola vez contra tu base de datos antes de arrancar el servidor.

CREATE TABLE IF NOT EXISTS usuarios (
  id SERIAL PRIMARY KEY,
  nombre TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  rol TEXT NOT NULL CHECK (rol IN ('empresa', 'taller')),
  organizacion TEXT NOT NULL,
  creado_en TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS talleres (
  id SERIAL PRIMARY KEY,
  usuario_id INTEGER UNIQUE NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  nombre TEXT NOT NULL,
  especialidad TEXT NOT NULL DEFAULT 'Camisería',
  ubicacion TEXT DEFAULT '',
  capacidad TEXT DEFAULT '',
  verificado BOOLEAN NOT NULL DEFAULT false,
  verificacion_pendiente BOOLEAN NOT NULL DEFAULT false,
  creado_en TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS resenas (
  id SERIAL PRIMARY KEY,
  taller_id INTEGER NOT NULL REFERENCES talleres(id) ON DELETE CASCADE,
  empresa_nombre TEXT NOT NULL,
  estrellas INTEGER NOT NULL CHECK (estrellas BETWEEN 1 AND 5),
  comentario TEXT DEFAULT '',
  creado_en TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pedidos (
  id SERIAL PRIMARY KEY,
  empresa_id INTEGER NOT NULL REFERENCES usuarios(id),
  taller_id INTEGER NOT NULL REFERENCES talleres(id),
  prenda TEXT NOT NULL,
  cantidad INTEGER NOT NULL CHECK (cantidad > 0),
  descripcion TEXT DEFAULT '',
  monto NUMERIC(12, 2) NOT NULL CHECK (monto > 0),
  estado TEXT NOT NULL DEFAULT 'Pendiente'
    CHECK (estado IN ('Pendiente', 'Aceptado', 'Rechazado', 'En proceso', 'Completado', 'Pagado')),
  pagado BOOLEAN NOT NULL DEFAULT false,
  calificado BOOLEAN NOT NULL DEFAULT false,
  mp_preference_id TEXT,
  mp_payment_id TEXT,
  creado_en TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mensajes (
  id SERIAL PRIMARY KEY,
  pedido_id INTEGER NOT NULL REFERENCES pedidos(id) ON DELETE CASCADE,
  autor_id INTEGER NOT NULL REFERENCES usuarios(id),
  autor_nombre TEXT NOT NULL,
  autor_rol TEXT NOT NULL,
  texto TEXT NOT NULL,
  creado_en TIMESTAMP DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pedidos_empresa ON pedidos(empresa_id);
CREATE INDEX IF NOT EXISTS idx_pedidos_taller ON pedidos(taller_id);
CREATE INDEX IF NOT EXISTS idx_mensajes_pedido ON mensajes(pedido_id);
CREATE INDEX IF NOT EXISTS idx_resenas_taller ON resenas(taller_id);
