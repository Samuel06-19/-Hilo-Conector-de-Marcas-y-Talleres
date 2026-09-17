import pg from "pg";
import "dotenv/config";

const { Pool } = pg;

// La mayoría de las bases gratuitas (Neon, Supabase, Render) requieren SSL.
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
});

export async function query(text, params) {
  return pool.query(text, params);
}
