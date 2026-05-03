export type OpenDeriskSeverity = 'critical' | 'high' | 'medium' | 'low'
export type Iso27035Phase = 'detect' | 'report' | 'assess' | 'respond' | 'learn'
export type NistFunction = 'IDENTIFY' | 'DETECT' | 'PROTECT' | 'RESPOND' | 'RECOVER'

export interface OpenDeriskIncident {
  incident_id: string
  timestamp: string
  severity: OpenDeriskSeverity
  category: string
  source: string
  machine: string
  technical_context: {
    active_processes?: string[]
    network_connections?: Array<{
      dest_ip: string
      dest_port: number
      protocol: string
      bytes_sent?: number
    }>
    modified_files_hashes?: string[]
    event_ids?: number[]
    log_snippets?: string[]
  }
  iso27035_phase: Iso27035Phase
  nist_function: NistFunction
}

export interface GuardianIncident {
  id: string
  createdAt?: Date | string
  created_at?: Date | string
  severity?: string | null
  category?: string | null
  source?: string | null
  machine?: string | null
  machine_id?: string | null
  workflow_phase?: string | null
  phase?: string | null
  nistFunction?: string | null
  details?: {
    processes?: string[]
    active_processes?: string[]
    connections?: unknown[]
    network_connections?: unknown[]
    fileHashes?: string[]
    modified_files_hashes?: string[]
    windowsEventIds?: number[]
    event_ids?: number[]
    logSnippets?: string[]
    log_snippets?: string[]
  }
  metadata?: {
    processes?: string[]
    active_processes?: string[]
    connections?: unknown[]
    network_connections?: unknown[]
    fileHashes?: string[]
    modified_files_hashes?: string[]
    windowsEventIds?: number[]
    event_ids?: number[]
    logSnippets?: string[]
    log_snippets?: string[]
  }
}

function normalizeSeverity(input: string | null | undefined): OpenDeriskSeverity {
  if (input === 'critical' || input === 'high' || input === 'medium' || input === 'low') {
    return input
  }
  return 'medium'
}

function normalizeIsoPhase(input: string | null | undefined): Iso27035Phase {
  const value = (input ?? '').toLowerCase()
  if (value === 'detect' || value === 'report' || value === 'assess' || value === 'respond' || value === 'learn') {
    return value
  }
  return 'assess'
}

function normalizeNistFunction(input: string | null | undefined, phase: Iso27035Phase): NistFunction {
  const value = (input ?? '').toUpperCase()
  if (value === 'IDENTIFY' || value === 'DETECT' || value === 'PROTECT' || value === 'RESPOND' || value === 'RECOVER') {
    return value
  }

  // Fallback mapping from ISO 27035 phase to NIST function.
  switch (phase) {
    case 'detect':
      return 'DETECT'
    case 'report':
      return 'IDENTIFY'
    case 'assess':
      return 'IDENTIFY'
    case 'respond':
      return 'RESPOND'
    case 'learn':
      return 'RECOVER'
    default:
      return 'DETECT'
  }
}

function processNameOnly(value: string): string {
  const normalized = value.replace(/\\/g, '/').trim()
  const lastPart = normalized.split('/').filter(Boolean).pop() ?? normalized
  return lastPart.slice(0, 120)
}

function anonymizeLogSnippet(value: string): string {
  return value
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED_EMAIL]')
    .replace(/C:\\Users\\[^\\\s]+/gi, 'C:\\Users\\REDACTED')
    .replace(/\+?\d[\d\s().-]{7,}\d/g, '[REDACTED_PHONE]')
    .slice(0, 1500)
}

function toIsoTimestamp(input: Date | string | undefined): string {
  const dt = input instanceof Date ? input : new Date(input ?? Date.now())
  return Number.isNaN(dt.getTime()) ? new Date().toISOString() : dt.toISOString()
}

function pickArray<T>(...candidates: Array<T[] | undefined>): T[] {
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      return candidate
    }
  }
  return []
}

function normalizeConnections(raw: unknown[]): OpenDeriskIncident['technical_context']['network_connections'] {
  const result: OpenDeriskIncident['technical_context']['network_connections'] = []

  for (const item of raw) {
    if (!item || typeof item !== 'object') continue

    const obj = item as Record<string, unknown>
    const destIp = String(obj.dest_ip ?? obj.destination_ip ?? obj.remote_ip ?? '').trim()
    const destPort = Number(obj.dest_port ?? obj.port)
    const protocol = String(obj.protocol ?? obj.proto ?? '').trim().toUpperCase()

    if (!destIp || !Number.isFinite(destPort) || !protocol) continue

    const bytesSentRaw = obj.bytes_sent ?? obj.bytes
    const bytesSent = Number(bytesSentRaw)

    result.push({
      dest_ip: destIp,
      dest_port: destPort,
      protocol,
      ...(Number.isFinite(bytesSent) ? { bytes_sent: bytesSent } : {}),
    })
  }

  return result
}

function normalizeHashes(raw: string[]): string[] {
  return raw
    .map((v) => String(v).trim().toLowerCase())
    .filter((v) => /^[a-f0-9]{64}$/.test(v))
}

function normalizeEventIds(raw: number[]): number[] {
  return raw
    .map((v) => Number(v))
    .filter((v) => Number.isInteger(v) && v >= 0)
}

export function formatForOpenDerisk(incident: GuardianIncident): OpenDeriskIncident {
  const context = incident.details ?? incident.metadata ?? {}
  const isoPhase = normalizeIsoPhase(incident.phase ?? incident.workflow_phase)

  const processes = pickArray(context.processes, context.active_processes)
  const connections = pickArray(context.connections, context.network_connections)
  const fileHashes = pickArray(context.fileHashes, context.modified_files_hashes)
  const eventIds = pickArray(context.windowsEventIds, context.event_ids)
  const logSnippets = pickArray(context.logSnippets, context.log_snippets)

  return {
    incident_id: incident.id,
    timestamp: toIsoTimestamp(incident.createdAt ?? incident.created_at),
    severity: normalizeSeverity(incident.severity),
    category: incident.category ?? 'other',
    source: `GUARDIAN_${String(incident.source ?? 'UNKNOWN').toUpperCase()}`,
    machine: incident.machine ?? incident.machine_id ?? 'UNKNOWN',
    technical_context: {
      active_processes: processes.map(processNameOnly).filter(Boolean),
      network_connections: normalizeConnections(connections),
      modified_files_hashes: normalizeHashes(fileHashes),
      event_ids: normalizeEventIds(eventIds),
      log_snippets: logSnippets.map(anonymizeLogSnippet).filter(Boolean),
    },
    iso27035_phase: isoPhase,
    nist_function: normalizeNistFunction(incident.nistFunction, isoPhase),
  }
}
