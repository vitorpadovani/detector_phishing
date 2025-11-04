import type { Signal } from '../types';

export function verdictFromScore(score: number): 'MALICIOSA'|'SUSPEITA'|'PROVAVELMENTE SEGURA' {
  return score >= 65 ? 'MALICIOSA' : score >= 35 ? 'SUSPEITA' : 'PROVAVELMENTE SEGURA';
}

export function totalScore(signals: Signal[]): number {
  return Math.min(100, signals.reduce((acc, s) => acc + (s.weight || 0), 0));
}
