import { mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Alert } from "./alert.js";
import type { AlertQueue } from "./coordinator-ports.js";

// The real transport: a directory of alert files. The feeder drops JSON in; the
// daemon pulls it out. Nothing in memory, so it survives a restart, and a claim is
// an atomic rename, so two pulls never hand out the same alert.

// Files are named with a timestamp prefix so a lexical sort is chronological, and
// the alert id keeps two alerts in the same millisecond from colliding.
export function enqueueAlert(dir: string, alert: Alert): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${Date.now()}-${alert.alert_id}.json`), JSON.stringify(alert, null, 2));
}

export class FileAlertQueue implements AlertQueue {
  constructor(private readonly dir: string) {}

  async pull(): Promise<Alert | null> {
    let files: string[];
    try {
      files = readdirSync(this.dir).filter((file) => file.endsWith(".json")).sort();
    } catch {
      // No queue dir yet: nothing to hand out.
      return null;
    }
    if (files.length === 0) return null;

    const source = join(this.dir, files[0]!);
    const claimed = `${source}.claimed`;
    try {
      // The claim: whoever renames it first owns it. A loser gets ENOENT and
      // simply reports the queue empty for this pull.
      renameSync(source, claimed);
    } catch {
      return null;
    }

    const alert = JSON.parse(readFileSync(claimed, "utf8")) as Alert;
    rmSync(claimed, { force: true });
    return alert;
  }
}
