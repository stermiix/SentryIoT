/* What the components draw: the screen's view of the log, already in pt-BR (times as "14:03:41").
   `src/adaptador.ts` builds these objects from the log events; the components never read the log. */
import type {
  AgentName, Category, Channel, EffectResult, EventType, ExecutionState, IncidentState, ModelCategory,
  ProposalState, ProviderLocation, Risk, RiskReason,
} from './vocab';

export interface LogEvent {
  /** Position in the log, 1-based (the replay cursor). */
  n: number;
  id: string;
  /** Local time, "14:03:41". */
  at: string;
  type: EventType;
  agent?: AgentName;
  incident?: string;
  /** Id of what the event is about: inc-0001, prop-0002, exec-0001. */
  ref?: string;
  /** System text. */
  text: string;
  detail?: string;
  tokens?: number;
  seconds?: number;
  location?: ProviderLocation;
  model?: string;
  windows?: number;
  channel?: Channel;
  user?: string;
  /** Text written by an agent (recommendation) or by a person (decision reason). */
  quote?: string;
  /** The log reader ignored this event: it did not fit the state where it appears. */
  ignored?: boolean;
}

export interface Incident {
  id: string;
  state: IncidentState;
  category?: Category;
  modelCategory: ModelCategory;
  confidence: number;
  windows: number;
  start: string;
  end: string;
  sources: number;
  destinations: number;
  /** Proposals waiting for a person. */
  awaiting: number;
  note?: string;
  service?: string;
}

export interface Proposal {
  id: string;
  incident: string;
  action: string;
  isNew?: boolean;
  /** The new action entered the catalogue. */
  promoted?: boolean;
  /** `free`: a new action's target written by the agent in its own words (agent text, not a label). */
  target: { label: string; address?: string; free?: boolean };
  duration?: string;
  risk: Risk;
  state: ProposalState;
  reasons?: RiskReason[];
  /** The decision agent's justification: agent text, shown as such. */
  justification?: string;
  /** A new action as the agent described it (agent text): what the person reads before approving. */
  newAction?: { description?: string; steps?: string[]; expected?: string; undo?: string; source?: string };
  decision?: { kind: 'aprovada' | 'rejeitada'; channel: Channel; user: string; at: string; reason?: string };
  executions?: { id: string; state: ExecutionState; at: string }[];
  effect?: { result: EffectResult; at: string };
  createdAt: string;
}

export interface Address { address: string; label: string; frames: number; role: 'origem' | 'destino' }

export interface FeatureRow { name: string; value: number; benign: number; decimals?: number }

export interface Provider { id: string; label: string; model: string; location: ProviderLocation; status: 'online' | 'offline' }
