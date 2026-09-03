import postgres from 'postgres';
import { drizzle } from 'drizzle-orm/postgres-js';
import * as schema from './schema.js';

const connectionString = process.env.DATABASE_URL ?? 'postgres://phantomvault:phantomvault@localhost:5432/phantomvault';

export const sql = postgres(connectionString, { max: 10 });
export const db = drizzle(sql, { schema });
export type Database = typeof db;
