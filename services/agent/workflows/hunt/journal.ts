import { EVENT_SCHEMA_VERSION, type NewEvent, type RunKind } from "../../contracts/events.js";
import type { State } from "../../core/seams.js";
import { fold, type HuntEvent, type HuntKinds, type Projection } from "./ledger.js";
import type { HuntState } from "./types.js";

export type Body = NewEvent<HuntKinds>;

// The controller's ledger, backed by the State seam. append stays synchronous so
// the decision logic reads unchanged; flush is what makes an iteration durable.
export class Journal {
  private events: HuntEvent[] = [];
  private pending: Body[] = [];
  private view: Projection | null = null;
  private written = 0;

  private constructor(
    private readonly state: State<HuntKinds>,
    readonly runId: string,
    private readonly runKind: RunKind,
  ) {}

  static async open(state: State<HuntKinds>, runId: string, runKind: RunKind = "hunt"): Promise<Journal> {
    const journal = new Journal(state, runId, runKind);
    journal.events = await state.read(runId);
    journal.written = journal.events.length;
    return journal;
  }

  static async create(state: State<HuntKinds>, runId: string, hunt: HuntState, runKind: RunKind = "hunt"): Promise<Journal> {
    const journal = new Journal(state, runId, runKind);
    journal.append({ kind: "run", payload: { hunt } } as unknown as Body);
    await journal.flush();
    return journal;
  }

  // Buffered, not written: an iteration lands as one transaction, so a crash
  // between two of its events cannot leave half an iteration on the ledger.
  append(body: Body): HuntEvent {
    const event = {
      ...body,
      run_id: this.runId,
      run_kind: this.runKind,
      seq: this.events.length,
      ts: new Date().toISOString(),
      schema_version: EVENT_SCHEMA_VERSION,
    } as HuntEvent;
    this.pending.push(body);
    this.events.push(event);
    this.view = null;
    return event;
  }

  patch(target: string, id: string, fields: Record<string, unknown>): void {
    this.append({ kind: "patch", payload: { target, id, fields } } as unknown as Body);
  }

  async flush(): Promise<void> {
    if (this.pending.length === 0) return;
    const batch = this.pending;
    this.pending = [];
    this.written = await this.state.append(this.runId, this.written, batch);
  }

  get projection(): Projection {
    if (this.view === null) this.view = fold(this.events);
    return this.view;
  }

  get log(): readonly HuntEvent[] {
    return this.events;
  }
}
