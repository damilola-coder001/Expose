import rules from '../rules.json';

export interface SecurityRules {
  category_weights: Record<string, number>;
  severity_penalties: Record<string, number>;
  letter_grades: Array<{ min_score: number; grade: string }>;
  not_assessed_boundaries: Array<{
    area: string;
    reason: string;
    explanation: string;
  }>;
}

export function getSecurityRules(): SecurityRules {
  return rules as SecurityRules;
}

export default rules;
