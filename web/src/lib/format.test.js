import { describe, expect, it } from 'vitest'
import { buildQuery } from './api.js'
import { formatDate, priorityLevel, severityLabel, tagLabel } from './format.js'

describe('Anzeigehilfen', () => {
  it('übersetzt Schweregrade', () => {
    expect(severityLabel('Critical')).toBe('Kritisch')
    expect(severityLabel('Unbekannt')).toBe('Unbekannt')
  })

  it('stuft Prioritäten ein', () => {
    expect(priorityLevel(95)).toBe('hoch')
    expect(priorityLevel(60)).toBe('mittel')
    expect(priorityLevel(10)).toBe('niedrig')
  })

  it('formatiert UTC-Datum deutsch', () => {
    expect(formatDate('2026-10-01T10:00:00')).toBe('01.10.2026')
    expect(formatDate('')).toBe('')
  })

  it('übersetzt bekannte Angriffsmerkmale', () => {
    expect(tagLabel('exploited-in-the-wild')).toBe('Aktiv ausgenutzt')
    expect(tagLabel('neu')).toBe('neu')
  })
})

describe('buildQuery', () => {
  it('lässt leere Filter weg', () => {
    expect(buildQuery({ search: '', severity: 'High', watchlistOnly: false, page: 2 })).toBe('?severity=High&page=2')
    expect(buildQuery({ search: '' })).toBe('')
  })

  it('kodiert Sonderzeichen', () => {
    expect(buildQuery({ search: 'a&b' })).toBe('?search=a%26b')
  })
})
