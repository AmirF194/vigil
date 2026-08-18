/* The hunt panel. Everything asserted here is data the projection already
   carried and the console used to throw away: gaps, checkpoints, escalations
   and the report itself were reachable only as prose, and only after terminal. */
import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { RunDetail } from './WorkflowsScreen'

vi.mock('../../../services/api', () => ({
  workflowApi: { steer: vi.fn(() => Promise.resolve({ data: {} })) },
  agentsApi: { listAgents: vi.fn(() => Promise.resolve({ data: { agents: [] } })) },
  findingsApi: { getAll: vi.fn(() => Promise.resolve({ data: { findings: [] } })) },
  casesApi: { getAll: vi.fn(() => Promise.resolve({ data: { cases: [] } })) },
}))
vi.mock('../../../services/skillsApi', () => ({
  skillsApi: { getAll: vi.fn(() => Promise.resolve({ data: { skills: [] } })) },
  SKILL_CATEGORIES: [],
}))

const hunt = (over = {}) => ({
  status: 'terminal',
  iteration: 5,
  evidence_count: 34,
  cost_usd: 4.1786,
  hypotheses: [
    {
      hypothesis_id: 'h-3431',
      statement: 'An internal host is beaconing on a regular interval',
      status: 'handed_off',
      attack_technique: 'T1071.001',
      resolution_reason: 'survived the argue-the-null pass',
      provenance: 'hunt_spec',
    },
  ],
  ...over,
})

const detail = (over = {}) => ({ run_id: 'run-1', status: 'completed', ...over })

const renderPanel = (over = {}) =>
  render(<RunDetail d={detail(over)} onSteered={() => {}} />)

describe('what a finished hunt shows an operator', () => {
  it('names each belief, its technique and where it stands', () => {
    renderPanel({ hunt: hunt() })

    expect(screen.getByText(/An internal host is beaconing/)).toBeInTheDocument()
    expect(screen.getByText('T1071.001')).toBeInTheDocument()
    expect(screen.getByText('handed_off')).toBeInTheDocument()
  })

  it('marks the belief the operator put up themselves', () => {
    renderPanel({
      hunt: hunt({
        hypotheses: [
          { hypothesis_id: 'h-1', statement: 'the definition asked this', status: 'active', provenance: 'hunt_spec' },
          { hypothesis_id: 'h-2', statement: 'I asked this', status: 'active', provenance: 'operator' },
        ],
      }),
    })

    const mine = screen.getByText('I asked this').closest('tr')!
    expect(within(mine).getByText('yours')).toBeInTheDocument()
    const theirs = screen.getByText('the definition asked this').closest('tr')!
    expect(within(theirs).queryByText('yours')).toBeNull()
  })

  it('shows the corroboration a verdict rested on', () => {
    renderPanel({
      hunt: hunt({
        report: {
          gaps: [],
          checkpoints: [],
          hypotheses: [
            {
              hypothesis_id: 'h-3431',
              evidence_strength: {
                corroborating_sources: 4,
                contradicting_records: 0,
                open_gaps: 0,
                attacker_influenceable_only: false,
                survived_disconfirmation: true,
              },
            },
          ],
        },
      }),
    })

    expect(screen.getByText(/4 corroborating source system\(s\)/)).toBeInTheDocument()
    expect(screen.getByText(/survived disconfirmation/)).toBeInTheDocument()
  })
})

// The payoff for declaring an unbound capability: an operator sees the hunt ran
// without a SIEM, rather than reading "nothing was proven" and drawing a
// conclusion about the estate from a fact about the deployment.
describe('what the hunt could not see', () => {
  const blind = {
    gaps: [
      {
        evidence_id: 'ev-1',
        iteration: 0,
        summary: 'no tool in this deployment answers telemetry_search',
        hypothesis_id: null,
      },
    ],
    checkpoints: [],
    hypotheses: [],
  }

  it('lists an unbound capability as a visibility gap', () => {
    renderPanel({ hunt: hunt({ report: blind }) })

    expect(screen.getByText('Visibility gaps (1)')).toBeInTheDocument()
    expect(screen.getByText(/answers telemetry_search/)).toBeInTheDocument()
  })

  it('says a gap that names no hypothesis is unattributed rather than blank', () => {
    renderPanel({ hunt: hunt({ report: blind }) })

    expect(screen.getByText('unattributed')).toBeInTheDocument()
  })

  it('shows no gap section at all when every query came back', () => {
    renderPanel({ hunt: hunt({ report: { gaps: [], checkpoints: [], hypotheses: [] } }) })

    expect(screen.queryByText(/Visibility gaps/)).toBeNull()
  })
})

describe('escalations and supervision', () => {
  it('links the case an escalation opened', () => {
    renderPanel({
      hunt: hunt({
        handoffs: [
          { case_id: 'case-25aac39c', hypothesis_id: 'h-3431', iteration: 4, rationale: 'isolate FYODOR-L first' },
        ],
      }),
    })

    expect(screen.getByText('Escalated to incident response (1)')).toBeInTheDocument()
    expect(screen.getByText('case-25aac39c')).toBeInTheDocument()
    expect(screen.getByText('isolate FYODOR-L first')).toBeInTheDocument()
  })

  it('shows where a human was asked and what they answered', () => {
    renderPanel({
      hunt: hunt({
        report: {
          gaps: [],
          hypotheses: [],
          checkpoints: [
            {
              checkpoint_id: 'cp-1',
              class: 'verdict_review',
              raised_iteration: 3,
              question: 'Mark h-3431 proven?',
              resolution: { answer: 'approve', actor: 'matthewmorris', text: 'approved' },
            },
          ],
        },
      }),
    })

    expect(screen.getByText('Mark h-3431 proven?')).toBeInTheDocument()
    expect(screen.getByText(/approve by matthewmorris/)).toBeInTheDocument()
  })

  it('says plainly when a checkpoint is still waiting on someone', () => {
    renderPanel({
      hunt: hunt({
        report: {
          gaps: [],
          hypotheses: [],
          checkpoints: [
            { checkpoint_id: 'cp-1', class: 'hypothesis_approval', question: 'Start this hunt?', resolution: null },
          ],
        },
      }),
    })

    expect(screen.getByText('still pending')).toBeInTheDocument()
  })
})

// result_summary only lands at terminal. A hunt that finished but whose row was
// not yet finalised would otherwise show its verdicts and no report.
describe('the report', () => {
  it('renders the hunt report as soon as the projection carries one', () => {
    renderPanel({ hunt: hunt({ report_markdown: '## Verdicts\n\nNothing was proven.' }) })

    expect(screen.getByRole('heading', { name: 'Hunt report' })).toBeInTheDocument()
    expect(screen.getByText('Nothing was proven.')).toBeInTheDocument()
  })

  it('prefers the hunt report over the run row summary', () => {
    renderPanel({
      result_summary: 'stale row copy',
      hunt: hunt({ report_markdown: 'the ledger says this' }),
    })

    expect(screen.getByText('the ledger says this')).toBeInTheDocument()
    expect(screen.queryByText('stale row copy')).toBeNull()
  })

  it('still shows a plain result summary for a run that is not a hunt', () => {
    renderPanel({ result_summary: 'phases all ran' })

    expect(screen.getByText('Result summary')).toBeInTheDocument()
    expect(screen.getByText('phases all ran')).toBeInTheDocument()
  })
})

// A fan-out dispatches one query_intent to every worker, so four failures printed
// the same 300-char intent four times with only the trailing reason differing.
describe('gaps read as questions, not as workers', () => {
  const same = (id: string, summary = 'worker failed: calls_exhausted') => ({
    evidence_id: id,
    iteration: 2,
    summary,
    query_intent: 'Determine reputation and ASN for 45.77.53.176',
    hypothesis_id: 'h-3431',
  })

  it('shows the question once and counts the workers', () => {
    renderPanel({
      hunt: hunt({
        report: {
          gaps: [same('ev-1'), same('ev-2'), same('ev-3', 'worker failed: timeout')],
          checkpoints: [],
          hypotheses: [],
        },
      }),
    })

    expect(screen.getAllByText(/Determine reputation and ASN/)).toHaveLength(1)
    expect(screen.getByText('3 workers, same question.')).toBeInTheDocument()
  })

  it('keeps every distinct reason', () => {
    renderPanel({
      hunt: hunt({
        report: {
          gaps: [same('ev-1'), same('ev-2', 'worker failed: timeout')],
          checkpoints: [],
          hypotheses: [],
        },
      }),
    })

    expect(screen.getByText('worker failed: calls_exhausted')).toBeInTheDocument()
    expect(screen.getByText('worker failed: timeout')).toBeInTheDocument()
  })

  // The header still counts records, not questions: three failed workers are
  // three blind spots even when they were blind to the same thing.
  it('still counts the records in the heading', () => {
    renderPanel({
      hunt: hunt({ report: { gaps: [same('ev-1'), same('ev-2')], checkpoints: [], hypotheses: [] } }),
    })

    expect(screen.getByText('Visibility gaps (2)')).toBeInTheDocument()
  })
})

// approve and reject have always been valid directives and the projection has
// always carried the open checkpoint. Nothing rendered it, so a parked hunt could
// be watched and not answered, and the only way out of one was to abort it.
describe('answering a checkpoint the hunt is parked on', () => {
  const parked = (over = {}) => ({
    run_id: 'run-1',
    checkpoint_id: 'cp-5d413252',
    checkpoint_class: 'budget_anomaly',
    question: 'Two consecutive worker dispatches have failed with 504 timeout errors.',
    ...over,
  })

  const withCheckpoint = (over = {}) =>
    renderPanel({ hunt: hunt({ run_id: 'run-1', open_checkpoint: parked(over) }) })

  it('shows what the run is waiting on rather than only that it waits', () => {
    withCheckpoint()

    expect(screen.getByText(/Two consecutive worker dispatches have failed/)).toBeInTheDocument()
    expect(screen.getByText(/Waiting on you · budget_anomaly/)).toBeInTheDocument()
  })

  it('sends the answer against the checkpoint it was raised for', async () => {
    const { workflowApi } = await import('../../../services/api')
    withCheckpoint()

    fireEvent.click(screen.getByRole('button', { name: 'approve' }))

    expect(workflowApi.steer).toHaveBeenCalledWith('run-1', 'approve', '', {
      checkpoint_id: 'cp-5d413252',
    })
  })

  it('carries the reason typed beside the buttons', async () => {
    const { workflowApi } = await import('../../../services/api')
    withCheckpoint()

    fireEvent.change(screen.getByPlaceholderText(/Why —/), { target: { value: 'timeout is fixed' } })
    fireEvent.click(screen.getByRole('button', { name: 'reject' }))

    expect(workflowApi.steer).toHaveBeenCalledWith('run-1', 'reject', 'timeout is fixed', {
      checkpoint_id: 'cp-5d413252',
    })
  })

  // The approval checkpoint carries them, and they are the reason an operator
  // would reject rather than approve.
  it('names the capabilities the run has no tool for', () => {
    withCheckpoint({ context: { unbound_capabilities: ['telemetry_search'] } })

    expect(screen.getByText(/No tool here answers telemetry_search/)).toBeInTheDocument()
  })

  it('shows nothing when the run is waiting on no one', () => {
    renderPanel({ hunt: hunt() })

    expect(screen.queryByText(/Waiting on you/)).toBeNull()
  })
})
