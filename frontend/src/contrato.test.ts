import { describe, expect, it } from "vitest";
import contrato from "../../codigo/mcp/contrato.json";
import fonteDasAcoes from "../../codigo/mcp/acoes.py?raw";
import { DADOS_DO_TIPO, DEFINICOES } from "./contrato";
import { ALVO_COM_ROTULO } from "./log";
import {
  ACOES_DE_BASE,
  AGENTES,
  CANAIS,
  CATEGORIAS,
  CATEGORIAS_DO_MODELO,
  CODIGOS_DE_RISCO_ALTO,
  COLUNAS,
  ESTADOS_DA_EXECUCAO,
  ESTADOS_DA_PROPOSTA,
  ESTADOS_DO_INCIDENTE,
  LUGARES_DO_MODELO,
  MAXIMO_DE_PASSOS,
  MAXIMO_DE_PROPOSTAS_POR_RECOMENDACAO,
  MOTIVOS_DE_PARADA,
  MOTIVOS_DE_RECUSA,
  MOTIVOS_DE_RISCO_ALTO,
  ORIGENS_DE_ACAO,
  PROTOCOLOS_DE_TRANSPORTE,
  RESULTADOS_DO_EFEITO,
  RISCOS,
  SEMPRE_DE_RISCO_ALTO,
  TEXTO_CURTO,
  TEXTO_LONGO,
  TIPOS_DE_EVENTO,
  VEREDITOS_DA_TRIAGEM,
} from "./listas";

// As listas da interface contra o contrato do MCP. Quando o contrato muda (um motivo de recusa
// novo, um campo novo numa proposta), este teste falha até a interface acompanhar, em vez de a
// linha nova do log ser descartada na tela.

type Esquema = { enum?: string[]; const?: string; required?: string[]; properties?: Record<string, Esquema>; maxLength?: number; maxItems?: number; items?: Esquema; anyOf?: Esquema[]; $ref?: string; propertyNames?: Esquema; discriminator?: { mapping: Record<string, string> } };
const definicoes = contrato.$defs as unknown as Record<string, Esquema>;

function propriedade(definicao: string, campo: string): Esquema {
  const esquema = definicoes[definicao].properties?.[campo];
  if (!esquema) {
    throw new Error(`o contrato não tem ${definicao}.${campo}`);
  }
  // Campo que aceita nulo vem como anyOf: [o tipo, null].
  return esquema.anyOf?.find((opcao) => opcao.enum || opcao.maxLength) ?? esquema;
}

const ordenado = (valores: readonly string[]) => [...valores].sort();

describe("listas de valores", () => {
  it.each([
    ["CATEGORIAS", CATEGORIAS, "Incidente", "categoria"],
    ["CATEGORIAS_DO_MODELO", CATEGORIAS_DO_MODELO, "Incidente", "categoria_do_modelo"],
    ["AGENTES", AGENTES, "ChamadaDeLLM", "agente"],
    ["CANAIS", CANAIS, "Decisao", "canal"],
    ["CANAIS", CANAIS, "MarcaDeResolvido", "canal"],
    ["RISCOS", RISCOS, "Proposta", "risco"],
    ["ESTADOS_DO_INCIDENTE", ESTADOS_DO_INCIDENTE, "Incidente", "estado"],
    ["ESTADOS_DA_PROPOSTA", ESTADOS_DA_PROPOSTA, "Proposta", "estado"],
    ["ESTADOS_DA_EXECUCAO", ESTADOS_DA_EXECUCAO, "Execucao", "estado"],
    ["RESULTADOS_DO_EFEITO", RESULTADOS_DO_EFEITO, "Efeito", "resultado"],
    ["ORIGENS_DE_ACAO", ORIGENS_DE_ACAO, "AcaoDoCatalogo", "origem"],
    ["PROTOCOLOS_DE_TRANSPORTE", PROTOCOLOS_DE_TRANSPORTE, "PortaContada", "protocolo"],
    ["CODIGOS_DE_RISCO_ALTO", CODIGOS_DE_RISCO_ALTO, "MotivoDeRiscoAlto", "codigo"],
    ["MOTIVOS_DE_RECUSA", MOTIVOS_DE_RECUSA, "Recusa", "motivo"],
    ["COLUNAS", COLUNAS, "FeaturePrincipal", "nome"],
    ["LUGARES_DO_MODELO", LUGARES_DO_MODELO, "ChamadaDeLLM", "onde"],
    ["MOTIVOS_DE_PARADA", MOTIVOS_DE_PARADA, "ConclusaoDoAgente", "motivo"],
    ["VEREDITOS_DA_TRIAGEM", VEREDITOS_DA_TRIAGEM, "ConclusaoDoAgente", "veredito"],
  ] as const)("%s é a lista de %s.%s", (_nome, lista, definicao, campo) => {
    expect(ordenado(lista)).toEqual(ordenado(propriedade(definicao, campo).enum ?? []));
  });

  it("as chaves de por_categoria são as categorias do modelo", () => {
    expect(ordenado(CATEGORIAS_DO_MODELO)).toEqual(ordenado(definicoes.LoteDeJanelas.properties!.por_categoria.propertyNames!.enum!));
  });

  it("a frase de cada motivo de risco alto é a do contrato", () => {
    expect(MOTIVOS_DE_RISCO_ALTO).toEqual(contrato.motivos_de_risco_alto);
  });

  it("os tipos de evento são os do contrato", () => {
    expect(ordenado(TIPOS_DE_EVENTO)).toEqual(ordenado(Object.keys(definicoes.Evento.discriminator!.mapping)));
  });
});

describe("campos de cada definição", () => {
  it("cada tipo de evento confere os dados com a definição que o contrato diz", () => {
    for (const [tipo, referencia] of Object.entries(definicoes.Evento.discriminator!.mapping)) {
      const evento = definicoes[referencia.replace("#/$defs/", "")];
      expect(evento.required).toEqual(["id", "instante", "tipo", "incidente", "dados"]);
      expect(evento.properties!.tipo.const ?? evento.properties!.tipo.enum).toContain(tipo);
      expect(DADOS_DO_TIPO.get(tipo as never), tipo).toBe(evento.properties!.dados.$ref!.replace("#/$defs/", ""));
    }
  });

  it.each(Object.keys(DEFINICOES))("%s confere os mesmos campos que o contrato tem", (nome) => {
    const definicao = definicoes[nome];
    const regra = DEFINICOES[nome];
    expect(ordenado(regra.campos), "obrigatórios").toEqual(ordenado(definicao.required ?? []));
    expect(ordenado([...regra.campos, ...regra.opcionais]), "todos").toEqual(ordenado(Object.keys(definicao.properties ?? {})));
  });

  it("os limites de texto e de listas são os do contrato", () => {
    expect(propriedade("Proposta", "id").maxLength).toBe(TEXTO_CURTO);
    expect(propriedade("Proposta", "justificativa").maxLength).toBe(TEXTO_LONGO);
    expect(propriedade("AcaoDoCatalogo", "passos").maxItems).toBe(MAXIMO_DE_PASSOS);
    expect(propriedade("Recomendacao", "propostas").maxItems).toBe(MAXIMO_DE_PROPOSTAS_POR_RECOMENDACAO);
    expect(propriedade("Proposta", "motivos_de_risco_alto").maxItems).toBe(CODIGOS_DE_RISCO_ALTO.length);
  });
});

// O catálogo de base e as ações sempre de risco alto não estão no contrato. O teste os lê no
// código do MCP, para que uma ação nova na base não deixe a reconstrução da interface para trás.
describe("regras do acoes.py que a reconstrução repete", () => {
  it("as ações da base são as de BASE", () => {
    const corpo = /^BASE = \{\n([\s\S]*?)^\}/m.exec(fonteDasAcoes)![1];
    const nomes = Array.from(corpo.matchAll(/^ {4}"(\w+)": _AcaoDeBase\(/gm), (achado) => achado[1]);
    expect(ordenado(ACOES_DE_BASE)).toEqual(ordenado(nomes));
  });

  it("as ações sempre de risco alto são as de _SEMPRE_DE_RISCO_ALTO", () => {
    const tupla = /^_SEMPRE_DE_RISCO_ALTO = \(([^)]*)\)/m.exec(fonteDasAcoes)![1];
    expect(ordenado(SEMPRE_DE_RISCO_ALTO)).toEqual(ordenado(Array.from(tupla.matchAll(/"(\w+)"/g), (achado) => achado[1])));
  });

  it("o formato do alvo com rótulo é o de _ALVO_COM_ROTULO", () => {
    const padrao = /^_ALVO_COM_ROTULO = re\.compile\(r"([^"]+)"\)/m.exec(fonteDasAcoes)![1];
    // O construtor do RegExp escapa a barra do mesmo jeito que a expressão literal da interface.
    expect(ALVO_COM_ROTULO.source).toBe(new RegExp(`^${padrao}$`).source);
  });
});
