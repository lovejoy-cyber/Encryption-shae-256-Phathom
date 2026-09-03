process.env.NODE_ENV = 'test';
process.env.DATABASE_URL ??= 'postgres://phantomvault:phantomvault@localhost:5432/phantomvault';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.MASTER_KEY_B64 ??= Buffer.from(new Uint8Array(32).fill(7)).toString('base64');
