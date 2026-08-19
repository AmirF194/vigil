/* The run modal. Everything here is a fact the deployment already knew and the
   console used to withhold until after the money was spent: what the run will
   cost at most, what it will not be able to look at, and where it went. */
import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { RunModal } from './WorkflowsScreen'

const execute = vi.fn(() => Promise.resolve({ data: { run_id: 'run-abc12345' } }))
const getWorkflow = vi.fn()
const getRun = vi.fn(() => Promise.resolve({ data: { run_id: 'run-abc12345', status: 'running' } }))

vi.mock('../../../services/api', () => ({
  workflowApi: {
    execute: (...a: unknown[]) => execute(...(a as [])),
    get: (...a: unknown[]) => getWorkflow(...(a as [])),
    getRun: (...a: unknown[]) => getRun(...(a as [])),
    steer: vi.fn(() => Promise.resolve({ data: {} })),
    cancelRun: vi.fn(() => Promise.resolve({ data: {} })),
  },
  agentsApi: { listAgents: vi.fn(() => Promise.resolve({ data: { agents: [] } })) },
  findingsApi: { getAll: vi.fn(() => Promise.resolve({ data: { findings: [] } })) },
  casesApi: { getAll: vi.fn(() => Promise.resolve({ data: { cases: [] } })) },
}))
vi.mock('../../../services/skillsApi', () => ({
  skillsApi: { getAll: vi.fn(() => Promise.resolve({ data: { skills: [] } })) },
  SKILL_CATEGORIES: [],
}))

const wf = (runKind = 'hunt') => ({
  id: 'threat-hunt', icon: 'flow' as const, name: 'Threat Hunt', desc: '',
  agents: [], cmds: [], source: 'file', useCase: '', runKind,
})

const limits = (unbound: string[]) => ({
  data: {
    capabilities: { bound: ['findings_search'], unbound },
    budgets: { max_iterations: 8, max_cost_usd: 3.0 },
  },
})

const open = (runKind = 'hunt') =>
  render(<RunModal wf={wf(runKind)} onStarted={() => {}} onClose={() => {}} />)

describe('what the hunt will not be able to see', () => {
  it('names an unbound capability before anything is spent', async () => {
    getWorkflow.mockResolvedValueOnce(limits(['telemetry_search']))
    open()

    expect(await screen.findByText(/No tool here answers telemetry_search/)).toBeInTheDocument()
  })

  // The distinction ADR 0015 exists for: without a SIEM the hunt proves nothing
  // whatever the estate looks like, and that reads identically to a clean estate.
  it('says a hunt without telemetry cannot corroborate anything', async () => {
    getWorkflow.mockResolvedValueOnce(limits(['telemetry_search']))
    open()

    expect(await screen.findByText(/a fact about this deployment, not about your estate/)).toBeInTheDocument()
  })

  it('says nothing at all when every capability bound', async () => {
    getWorkflow.mockResolvedValueOnce(limits([]))
    open()

    await waitFor(() => expect(getWorkflow).toHaveBeenCalled())
    expect(screen.queryByText(/No tool here answers/)).toBeNull()
  })
})

describe('what the run will cost', () => {
  it('states the ceiling rather than estimating a total', async () => {
    getWorkflow.mockResolvedValueOnce(limits([]))
    open()

    expect(await screen.findByText(/It stops at \$3\.00 whatever happens/)).toBeInTheDocument()
  })

  it('counts the turns the operator actually asked for', async () => {
    getWorkflow.mockResolvedValueOnce(limits([]))
    open()
    await screen.findByText(/It stops at/)

    fireEvent.change(screen.getByLabelText(/Iterations/), { target: { value: '3' } })

    expect(await screen.findByText(/^3 turn\(s\)/)).toBeInTheDocument()
  })

  it('sends the ceiling the operator typed, not the shipped one', async () => {
    getWorkflow.mockResolvedValueOnce(limits([]))
    open()
    await screen.findByText(/It stops at/)

    fireEvent.change(screen.getByLabelText('Context'), { target: { value: 'beaconing' } })
    fireEvent.change(screen.getByLabelText(/Hypothesis/), { target: { value: 'a host beacons' } })
    fireEvent.change(screen.getByLabelText(/Cost ceiling/), { target: { value: '25' } })
    expect(await screen.findByText(/It stops at \$25\.00 whatever happens/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Run workflow/ }))

    await waitFor(() => expect(execute).toHaveBeenCalledWith('threat-hunt', {
      context: 'beaconing', hypothesis: 'a host beacons', max_cost_usd: 25,
    }))
  })

  it('refuses to start on a ceiling that is not money', async () => {
    getWorkflow.mockResolvedValueOnce(limits([]))
    open()
    await screen.findByText(/It stops at/)

    fireEvent.change(screen.getByLabelText('Context'), { target: { value: 'beaconing' } })
    fireEvent.change(screen.getByLabelText(/Hypothesis/), { target: { value: 'a host beacons' } })
    fireEvent.change(screen.getByLabelText(/Cost ceiling/), { target: { value: '-3' } })

    expect(await screen.findByText(/above 0 and no more than 100/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Run workflow/ })).toBeDisabled()
  })

  it('offers no iterations field for a workflow that walks phases', async () => {
    getWorkflow.mockResolvedValueOnce({ data: {} })
    open('compose')

    await waitFor(() => expect(getWorkflow).toHaveBeenCalled())
    expect(screen.queryByLabelText(/Iterations/)).toBeNull()
  })
})

describe('after the run starts', () => {
  it('stays open on the run it started rather than closing on it', async () => {
    getWorkflow.mockResolvedValueOnce(limits([]))
    open()
    await screen.findByText(/It stops at/)

    fireEvent.change(screen.getByLabelText('Context'), { target: { value: 'beaconing on the finance subnet' } })
    fireEvent.change(screen.getByLabelText(/Hypothesis/), { target: { value: 'a host beacons' } })
    fireEvent.click(screen.getByRole('button', { name: /Run workflow/ }))

    expect(await screen.findByText(/It runs on the server whether this stays open or not/)).toBeInTheDocument()
    expect(await screen.findByText('run-abc1')).toBeInTheDocument()
  })
})

describe('a hunt tests what the operator states', () => {
  it('will not start on a target with no belief to test', async () => {
    getWorkflow.mockResolvedValueOnce(limits([]))
    open()
    await screen.findByText(/It stops at/)

    fireEvent.change(screen.getByLabelText('Context'), { target: { value: 'beaconing' } })

    expect(screen.getByRole('button', { name: /Run workflow/ })).toBeDisabled()
  })

  it('starts once a belief is stated', async () => {
    getWorkflow.mockResolvedValueOnce(limits([]))
    open()
    await screen.findByText(/It stops at/)

    fireEvent.change(screen.getByLabelText('Context'), { target: { value: 'beaconing' } })
    fireEvent.change(screen.getByLabelText(/Hypothesis/), { target: { value: 'a host beacons' } })

    expect(screen.getByRole('button', { name: /Run workflow/ })).not.toBeDisabled()
  })

  // A phase-walking workflow states its own phases and needs no belief.
  it('asks a phase workflow for no hypothesis', async () => {
    getWorkflow.mockResolvedValueOnce({ data: {} })
    open('compose')
    await waitFor(() => expect(getWorkflow).toHaveBeenCalled())

    fireEvent.change(screen.getByLabelText('Context'), { target: { value: 'ransomware on HOST-42' } })

    expect(screen.getByRole('button', { name: /Run workflow/ })).not.toBeDisabled()
  })
})
