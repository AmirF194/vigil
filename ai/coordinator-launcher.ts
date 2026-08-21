import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { HuntLauncher } from "./coordinator-ports.js";

// The existing CLI runner, located relative to this module so the daemon can be
// started from any working directory.
const VIGILHUNT = join(dirname(fileURLToPath(import.meta.url)), "..", "cli", "vigilhunt.ts");

// Runs a started hunt by spawning the CLI's own resume path as a detached child.
// The coordinator does not wait on it: the hunt takes its own lease and advances
// itself, and the coordinator stays free to handle the next alert. Reuses the
// whole run loop — lease, LLM providers, tools — with nothing duplicated here.
export class SpawnHuntLauncher implements HuntLauncher {
  constructor(private readonly iterations: number) {}

  launch(ledgerPath: string): void {
    const child = spawn(
      "npx",
      ["tsx", VIGILHUNT, "--resume", ledgerPath, "--iterations", String(this.iterations)],
      { detached: true, stdio: "ignore" },
    );
    child.unref();
  }
}
