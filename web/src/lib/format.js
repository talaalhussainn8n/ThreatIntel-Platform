// Anzeigehilfen für das Lagebild.

export const severityLabels = {
  Critical: 'Kritisch',
  High: 'Hoch',
  Medium: 'Mittel',
  Low: 'Niedrig',
  Unknown: 'Unbewertet'
}

export const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Unknown']

export function severityLabel(severity) {
  return severityLabels[severity] ?? severity
}

/** Farbstufe der Priorität: rot ab 80, orange ab 60, sonst grau. */
export function priorityLevel(priority) {
  if (priority >= 80) return 'hoch'
  if (priority >= 60) return 'mittel'
  return 'niedrig'
}

export function formatDate(value) {
  if (!value) return ''
  const date = new Date(value.endsWith('Z') ? value : `${value}Z`)
  return date.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' })
}

const tagLabels = {
  'remote-code-execution': 'Codeausführung',
  'exploited-in-the-wild': 'Aktiv ausgenutzt',
  unauthenticated: 'Ohne Anmeldung',
  'privilege-escalation': 'Rechteausweitung',
  'sql-injection': 'SQL-Injection',
  'cross-site-scripting': 'XSS',
  'authentication-bypass': 'Anmeldung umgehbar',
  'denial-of-service': 'Dienstausfall'
}

export function tagLabel(tag) {
  return tagLabels[tag] ?? tag
}
