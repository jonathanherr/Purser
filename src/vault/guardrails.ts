/**
 * Hard limits for anything that could move money. These live in code and config, never in agent
 * prompts, and are checked when a proposal is created and again by an executor before it runs
 * (executors arrive in phase 2).
 */
export interface Guardrails {
  perTransferCapUsd: number;
  perTradeCapUsd: number;
  monthlyCapUsd: number;
  twoPersonThresholdUsd: number;
  /** Changes to a recurring transfer always need both people. */
  twoPersonForRecurringTransfers: boolean;
  allowedTickers: string[];
  allowedDestinationTypes: string[];
  proposalTtlHours: number;
  maxProposalsPerAgentPerDay: number;
}

export const DEFAULT_GUARDRAILS: Guardrails = {
  perTransferCapUsd: 1_000,
  perTradeCapUsd: 2_500,
  monthlyCapUsd: 5_000,
  twoPersonThresholdUsd: 1_000,
  twoPersonForRecurringTransfers: true,
  allowedTickers: ['VTI', 'VXUS', 'BND', 'VOO', 'SCHB'],
  allowedDestinationTypes: ['depository', 'investment', 'credit'],
  proposalTtlHours: 48,
  maxProposalsPerAgentPerDay: 20,
};
