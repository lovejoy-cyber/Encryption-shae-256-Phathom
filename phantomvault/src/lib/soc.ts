/**
 * Lightweight SOC-style event log + correlation.
 *
 * Every sensitive action across the app (unlock attempts, duress triggers,
 * vault access, key rotation, file scans, B2B share access) is appended
 * here as an immutable event. runCorrelation() turns raw events into
 * human-triage-able "investigations" — the same shape a real SOC analyst
 * works from, just scaled down to a single device's local log.
 */

import { get, set } from "idb-keyval";

export type EventType =
  | "vault_unlock"
  | "duress_unlock"
  | "failed_unlock"
  | "vault_item_added"
  | "vault_item_accessed"
  | "key_rotated"
  | "message_encrypted"
  | "message_decrypted"
  | "message_blocked"
  | "file_scan_flagged"
  | "b2b_file_shared"
  | "b2b_file_accessed"
  | "stego_locked"
  | "stego_extracted"
  | "metadata_stripped";

export type Severity = "info" | "warning" | "critical";

export interface SecurityEvent {
  id: string;
  type: EventType;
  severity: Severity;
  detail?: string;
  timestamp: number;
}

const LOG_KEY = "pv-soc-log";
const MAX_EVENTS = 2000;

export async function logEvent(e: Omit<SecurityEvent, "id" | "timestamp">): Promise<SecurityEvent> {
  const event: SecurityEvent = { ...e, id: crypto.randomUUID(), timestamp: Date.now() };
  const log: SecurityEvent[] = (await get(LOG_KEY)) ?? [];
  log.push(event);
  if (log.length > MAX_EVENTS) log.splice(0, log.length - MAX_EVENTS);
  await set(LOG_KEY, log);
  return event;
}

export async function getEvents(limit = 200): Promise<SecurityEvent[]> {
  const log: SecurityEvent[] = (await get(LOG_KEY)) ?? [];
  return log.slice(-limit).reverse();
}

export interface Investigation {
  title: string;
  severity: Severity;
  events: SecurityEvent[];
  summary: string;
  latestTimestamp: number;
}

/** Correlates raw events into investigations. Deliberately simple, rule-based — swap in a real detection pipeline for the enterprise tier. */
export async function runCorrelation(): Promise<Investigation[]> {
  const log: SecurityEvent[] = (await get(LOG_KEY)) ?? [];
  const investigations: Investigation[] = [];

  const failed = log.filter((e) => e.type === "failed_unlock").sort((a, b) => a.timestamp - b.timestamp);
  for (let i = 0; i + 2 < failed.length; i++) {
    const window = failed.slice(i, i + 3);
    if (window[2].timestamp - window[0].timestamp <= 5 * 60 * 1000) {
      investigations.push({
        title: "Possible brute-force unlock attempt",
        severity: "critical",
        events: window,
        summary: `${window.length} failed unlock attempts within 5 minutes.`,
        latestTimestamp: window[window.length - 1].timestamp,
      });
      i += 2;
    }
  }

  for (const e of log.filter((ev) => ev.type === "duress_unlock")) {
    investigations.push({
      title: "Duress password used — decoy vault opened",
      severity: "critical",
      events: [e],
      summary: "The app was unlocked with the duress password. The real vault was not exposed.",
      latestTimestamp: e.timestamp,
    });
  }

  for (const e of log.filter((ev) => ev.type === "file_scan_flagged")) {
    investigations.push({
      title: "File scanner flagged a suspicious file",
      severity: "warning",
      events: [e],
      summary: e.detail ?? "A file failed integrity/type validation before entering the vault.",
      latestTimestamp: e.timestamp,
    });
  }

  return investigations.sort((a, b) => b.latestTimestamp - a.latestTimestamp);
}

export async function clearLog(): Promise<void> {
  await set(LOG_KEY, []);
}
