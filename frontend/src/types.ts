// Tipos mínimos do log de eventos que a interface lê. Não é o contrato inteiro de
// `codigo/mcp/tipos.py` — só os campos que as telas 1 e 2 usam. `dados` fica solto (Record)
// porque o formato muda conforme `tipo`; os componentes leem só os campos que precisam.
export interface Evento {
  id: string;
  instante: string;
  tipo: string;
  incidente: string | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  dados: Record<string, any>;
}

export interface FeaturePrincipal {
  nome: string;
  valor: number;
  referencia_benigno: number;
}

export interface Incidente {
  id: string;
  estado: "aberto" | "encerrado";
  categoria: string;
  categoria_do_modelo: string;
  confianca: number;
  janelas: number;
  origens_distintas: number;
  distribuido: boolean;
  features_principais: FeaturePrincipal[];
}

export interface IncidenteView {
  id: string;
  incidente: Incidente | null;
  eventos: Evento[];
  chamadasLLM: number;
  tokensEntrada: number;
  tokensSaida: number;
  recomendacoes: Evento[];
}

export interface ResumoGeral {
  janelasClassificadas: number;
  totalIncidentes: number;
  chamadasLLM: number;
  tokens: number;
}
