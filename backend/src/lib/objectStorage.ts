/**
 * Encrypted blob storage (MinIO in this reference deployment; swap the
 * endpoint for AWS S3/Cloudflare R2 in production — same S3 API, no code
 * change). Every object written here is already outer-enveloped ciphertext
 * (docs/ARCHITECTURE.md §5.2) — this module is deliberately dumb: it never
 * sees a key, only opaque bytes and a random object key.
 */
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadBucketCommand, CreateBucketCommand } from '@aws-sdk/client-s3';
import { env } from './env.js';

const BUCKET = 'phantomvault-capabilities';

const client = new S3Client({
  endpoint: env.S3_ENDPOINT,
  region: 'us-east-1',
  forcePathStyle: true, // required for MinIO
  credentials: { accessKeyId: env.S3_ACCESS_KEY, secretAccessKey: env.S3_SECRET_KEY },
});

async function streamToBuffer(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

export async function putBlob(key: string, bytes: Uint8Array): Promise<void> {
  await client.send(new PutObjectCommand({ Bucket: BUCKET, Key: key, Body: bytes }));
}

export async function getBlob(key: string): Promise<Uint8Array> {
  const res = await client.send(new GetObjectCommand({ Bucket: BUCKET, Key: key }));
  const buf = await streamToBuffer(res.Body as NodeJS.ReadableStream);
  return new Uint8Array(buf);
}

export async function deleteBlob(key: string): Promise<void> {
  await client.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
}

/** Idempotent — call once at server startup. MinIO/S3 buckets aren't auto-created. */
export async function ensureBucket(): Promise<void> {
  try {
    await client.send(new HeadBucketCommand({ Bucket: BUCKET }));
  } catch {
    await client.send(new CreateBucketCommand({ Bucket: BUCKET }));
  }
}

export { BUCKET as CAPABILITIES_BUCKET };
