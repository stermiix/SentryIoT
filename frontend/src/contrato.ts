import {
  AGENTES,
  CANAIS,
  CATEGORIAS,
  CATEGORIAS_DO_MODELO,
  CODIGOS_DE_RISCO_ALTO,
  COLUNAS,
  DESTINOS_DO_CANDIDATO,
  ESTADOS_DA_EXECUCAO,
  ESTADOS_DA_PROPOSTA,
  ESTADOS_DO_INCIDENTE,
  LUGARES_DO_MODELO,
  MAXIMO_DE_CANDIDATOS,
  MAXIMO_DE_PASSOS,
  MAXIMO_DE_PROPOSTAS_POR_RECOMENDACAO,
  MOTIVOS_DE_PARADA,
  MOTIVOS_DE_RECUSA,
  ORIGENS_DE_ACAO,
  PORTAS_DO_CANDIDATO,
  PROTOCOLOS_DE_TRANSPORTE,
  RESULTADOS_DO_EFEITO,
  RISCOS,
  TEXTO_CURTO,
  TEXTO_LONGO,
  VEREDITOS_DA_TRIAGEM,
} from "./listas";
import type { Evento, TipoDeEvento } from "./types";

// Conferência de cada linha do log contra o contrato (`codigo/mcp/contrato.json`): campos
// obrigatórios, tipos, valores aceitos, limites de texto, endereços IP e nomes de feature, tipo de
// evento por tipo de evento. As regras de sequência (aprovar só proposta que aguarda, por exemplo)
// ficam em `log.ts`.
//
// Onde a conferência é mais frouxa que a do Python: campo a mais não derruba a linha, porque o
// contrato pode ganhar campos antes de a interface ser atualizada e o que a interface não lê não
// muda a tela; inteiro acima de 2^53 é recusado aqui e aceito lá; e a classificação dos caracteres
// do Unicode é a do navegador, que pode ser de outra versão que a do Python.

// Os padrões de `tipos.py`.
const UMA_LINHA = /^[^\x00-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]*$/;
const PARAGRAFOS = /^[^\x00-\x09\x0b-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]*$/;
const NOME_DE_ACAO = /^[a-z][a-z0-9_]{0,59}$/;
// Além do padrão, o texto só tem letras, marcas, números, pontuação, símbolos, espaços e a quebra de
// linha, e nenhum dos preenchimentos que aparecem em branco (`invisivel`, em `tipos.py`).
const INVISIVEL = /[^\p{L}\p{M}\p{N}\p{P}\p{S}\p{Zs}\n]|[\u115f\u1160\u2800\u3164\uffa0]/u;
// O instante sai do Python como `2026-10-20T14:03:41.004000Z`: data e hora com fuso, sempre.
const INSTANTE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const OCTETO = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IPV4 = new RegExp(`^${OCTETO}(?:\\.${OCTETO}){3}$`);

/** Devolve onde está o primeiro problema (`dados.janelas`, por exemplo), ou null se o valor serve. */
export type Regra = (valor: unknown, caminho: string) => string | null;
/** A regra de um objeto, com os nomes dos campos que ela confere, para o teste contra o contrato. */
export type RegraDeObjeto = Regra & { campos: readonly string[]; opcionais: readonly string[] };

function ehObjeto(valor: unknown): valor is Record<string, unknown> {
  return typeof valor === "object" && valor !== null && !Array.isArray(valor);
}

function temCampo(objeto: Record<string, unknown>, nome: string): boolean {
  return Object.prototype.hasOwnProperty.call(objeto, nome);
}

/** Milissegundos desde 1970 de um instante do log, ou NaN. Corta a fração em milissegundos antes de ler. */
export function instanteEmMs(texto: string): number {
  return INSTANTE.test(texto) ? Date.parse(texto.replace(/(\.\d{3})\d+/, "$1")) : Number.NaN;
}

/** Endereço IPv4 ou IPv6 sem zona, como o `endereco_canonico` de `tipos.py` aceita. */
export function ehEnderecoIP(texto: string): boolean {
  if (IPV4.test(texto)) {
    return true;
  }
  if (!texto.includes(":") || texto.includes("%") || texto.includes("[") || texto.includes("]")) {
    return false;
  }
  // O leitor de URL do navegador sabe ler um IPv6 inteiro, com `::` e com IPv4 no fim.
  try {
    new URL(`http://[${texto}]/`);
    return true;
  } catch {
    return false;
  }
}

function texto(maximo = TEXTO_CURTO, padrao = UMA_LINHA): Regra {
  return (valor, caminho) => {
    if (typeof valor !== "string" || !padrao.test(valor) || INVISIVEL.test(valor)) {
      return caminho;
    }
    // O Python apara os espaços antes de medir e conta pontos de código, e não unidades UTF-16.
    const tamanho = Array.from(valor.trim()).length;
    return tamanho >= 1 && tamanho <= maximo ? null : caminho;
  };
}

function umDe(valores: readonly string[]): Regra {
  return (valor, caminho) => (typeof valor === "string" && valores.includes(valor) ? null : caminho);
}

function inteiro(minimo: number): Regra {
  return (valor, caminho) => (Number.isSafeInteger(valor) && (valor as number) >= minimo ? null : caminho);
}

function numero(minimo = Number.NEGATIVE_INFINITY, maximo = Number.POSITIVE_INFINITY): Regra {
  return (valor, caminho) =>
    typeof valor === "number" && Number.isFinite(valor) && valor >= minimo && valor <= maximo ? null : caminho;
}

const contagem = inteiro(0);
// Porta de 1 a 65535, como `Porta` em `tipos.py`.
const porta: Regra = (valor, caminho) =>
  Number.isSafeInteger(valor) && (valor as number) >= 1 && (valor as number) <= 65_535 ? null : caminho;
const booleano: Regra = (valor, caminho) => (typeof valor === "boolean" ? null : caminho);
const instante: Regra = (valor, caminho) =>
  typeof valor === "string" && Number.isFinite(instanteEmMs(valor)) ? null : caminho;
const enderecoIP: Regra = (valor, caminho) =>
  typeof valor === "string" && valor.length <= 45 && ehEnderecoIP(valor) ? null : caminho;
const livre: Regra = (valor, caminho) => (ehObjeto(valor) ? null : caminho);
const nomeDeAcao = texto(60, NOME_DE_ACAO);
const textoLongo = texto(TEXTO_LONGO);
const paragrafos = texto(TEXTO_LONGO, PARAGRAFOS);
// O texto da análise e o do sumário só vêm da triagem (`Literal["triagem"]`, em `tipos.py`).
const daTriagem = umDe(["triagem"]);

function ouNulo(regra: Regra): Regra {
  return (valor, caminho) => (valor === null ? null : regra(valor, caminho));
}

function lista(regra: Regra, maximo = Number.POSITIVE_INFINITY, minimo = 0): Regra {
  return (valor, caminho) => {
    if (!Array.isArray(valor) || valor.length < minimo || valor.length > maximo) {
      return caminho;
    }
    for (let indice = 0; indice < valor.length; indice += 1) {
      const problema = regra(valor[indice], `${caminho}[${indice}]`);
      if (problema) {
        return problema;
      }
    }
    return null;
  };
}

/** Objeto com os campos obrigatórios `campos` e, se vierem, os de `opcionais`. */
function objeto(campos: Record<string, Regra>, opcionais: Record<string, Regra> = {}): RegraDeObjeto {
  const regra: Regra = (valor, caminho) => {
    if (!ehObjeto(valor)) {
      return caminho;
    }
    for (const [nome, regraDoCampo] of Object.entries(campos)) {
      if (!temCampo(valor, nome)) {
        return `${caminho}.${nome}`;
      }
      const problema = regraDoCampo(valor[nome], `${caminho}.${nome}`);
      if (problema) {
        return problema;
      }
    }
    for (const [nome, regraDoCampo] of Object.entries(opcionais)) {
      if (temCampo(valor, nome) && valor[nome] !== undefined) {
        const problema = regraDoCampo(valor[nome], `${caminho}.${nome}`);
        if (problema) {
          return problema;
        }
      }
    }
    return null;
  };
  return Object.assign(regra, { campos: Object.keys(campos), opcionais: Object.keys(opcionais) });
}

function mapa(chave: Regra, regraDoValor: Regra): Regra {
  return (valor, caminho) => {
    if (!ehObjeto(valor)) {
      return caminho;
    }
    for (const [nome, item] of Object.entries(valor)) {
      const problema = chave(nome, `${caminho}.${nome}`) ?? regraDoValor(item, `${caminho}.${nome}`);
      if (problema) {
        return problema;
      }
    }
    return null;
  };
}

const EnderecoContado = objeto({ endereco: enderecoIP, quadros: contagem });
const PortaContada = objeto({
  destino: enderecoIP,
  porta,
  protocolo: umDe(PROTOCOLOS_DE_TRANSPORTE),
  quadros: contagem,
});
const FeaturePrincipal = objeto({ nome: umDe(COLUNAS), valor: numero(), referencia_benigno: numero() });
const PortaDoCandidato = objeto({ porta, protocolo: umDe(PROTOCOLOS_DE_TRANSPORTE), quadros: contagem });
const CandidatoAAtacante = objeto({
  endereco: enderecoIP,
  janelas: contagem,
  no_trafego_normal: numero(0, 1),
  quadros_enviados: contagem,
  quadros_recebidos: contagem,
  conexoes_abertas: contagem,
  conexoes_recebidas: contagem,
  destinos: lista(EnderecoContado, DESTINOS_DO_CANDIDATO),
}, {
  // Opcional: o contrato dá uma lista vazia quando o campo não vem.
  portas: lista(PortaDoCandidato, PORTAS_DO_CANDIDATO),
});
const Incidente = objeto({
  id: texto(),
  estado: umDe(ESTADOS_DO_INCIDENTE),
  categoria: umDe(CATEGORIAS),
  categoria_do_modelo: umDe(CATEGORIAS_DO_MODELO),
  confianca: numero(0, 1),
  inicio: instante,
  fim: instante,
  janelas: inteiro(1),
  origens_distintas: contagem,
  distribuido: booleano,
  origens: lista(EnderecoContado),
  destinos: lista(EnderecoContado),
  features_principais: lista(FeaturePrincipal),
}, {
  // Opcional: o log gravado antes da versão 0.4.0 do contrato não tem as portas.
  portas: lista(PortaContada),
  // Opcionais: o log gravado antes da versão 0.6.0 do contrato não os tem.
  janelas_por_categoria: mapa(umDe(CATEGORIAS_DO_MODELO), contagem),
  candidatos: lista(CandidatoAAtacante, MAXIMO_DE_CANDIDATOS),
});
const MotivoDeRiscoAlto = objeto({ codigo: umDe(CODIGOS_DE_RISCO_ALTO), descricao: textoLongo });
const Execucao = objeto({
  id: texto(),
  proposta: texto(),
  incidente: texto(),
  acao: nomeDeAcao,
  alvo: texto(),
  parametros: livre,
  estado: umDe(ESTADOS_DA_EXECUCAO),
  aplicada_em: instante,
  desfeita_em: ouNulo(instante),
});
const ParametroDeAcao = objeto({ nome: texto(), descricao: textoLongo, obrigatorio: booleano });
const AcaoDoCatalogo = objeto({
  nome: nomeDeAcao,
  descricao: textoLongo,
  alvo: textoLongo,
  parametros: lista(ParametroDeAcao),
  regra: textoLongo,
  origem: umDe(ORIGENS_DE_ACAO),
  passos: lista(textoLongo, MAXIMO_DE_PASSOS),
  efeito_esperado: ouNulo(textoLongo),
  como_desfazer: textoLongo,
  fonte: ouNulo(texto()),
});

/** As regras de cada definição do contrato que aparece num evento, pelo nome dela em `$defs`. */
export const DEFINICOES: Record<string, RegraDeObjeto> = {
  EnderecoContado,
  PortaContada,
  FeaturePrincipal,
  PortaDoCandidato,
  CandidatoAAtacante,
  Incidente,
  MotivoDeRiscoAlto,
  Execucao,
  ParametroDeAcao,
  AcaoDoCatalogo,
  LoteDeJanelas: objeto({ janelas: contagem, por_categoria: mapa(umDe(CATEGORIAS_DO_MODELO), contagem) }),
  MarcaDeResolvido: objeto({ incidente: texto(), canal: umDe(CANAIS), usuario: texto(), motivo: ouNulo(textoLongo) }),
  ChamadaDeLLM: objeto({
    agente: umDe(AGENTES),
    modelo: texto(),
    tokens_entrada: contagem,
    tokens_saida: contagem,
    duracao_ms: numero(0),
  }, {
    // Opcionais: o log gravado antes da versão 0.5.0 do contrato não os tem.
    motivo_termino: ouNulo(texto()),
    onde: ouNulo(umDe(LUGARES_DO_MODELO)),
  }),
  ConclusaoDoAgente: objeto({
    agente: umDe(AGENTES),
    motivo: umDe(MOTIVOS_DE_PARADA),
    voltas: contagem,
    tokens_entrada: contagem,
    tokens_saida: contagem,
    veredito: ouNulo(umDe(VEREDITOS_DA_TRIAGEM)),
  }),
  ChamadaDeTool: objeto({
    agente: ouNulo(umDe(AGENTES)),
    nome: texto(),
    argumentos: livre,
    resultado: livre,
    duracao_ms: numero(0),
  }),
  AtacanteApontado: objeto({ endereco: enderecoIP, justificativa: textoLongo }),
  AnaliseDaTriagem: objeto({ agente: daTriagem, texto: paragrafos, veredito: ouNulo(umDe(VEREDITOS_DA_TRIAGEM)) }),
  Recomendacao: objeto({
    agente: umDe(AGENTES),
    texto: paragrafos,
    propostas: lista(texto(), MAXIMO_DE_PROPOSTAS_POR_RECOMENDACAO),
  }),
  Sumario: objeto({ agente: daTriagem, texto: paragrafos }),
  Proposta: objeto({
    id: texto(),
    incidente: texto(),
    acao: nomeDeAcao,
    alvo: texto(),
    alvo_com_rotulo: ouNulo(texto()),
    parametros: livre,
    justificativa: textoLongo,
    nova: booleano,
    risco: umDe(RISCOS),
    motivos_de_risco_alto: lista(MotivoDeRiscoAlto, CODIGOS_DE_RISCO_ALTO.length),
    exige_aprovacao: booleano,
    estado: umDe(ESTADOS_DA_PROPOSTA),
  }),
  Decisao: objeto({ proposta: texto(), canal: umDe(CANAIS), usuario: texto(), motivo: ouNulo(textoLongo) }),
  Efeito: objeto({
    execucao: texto(),
    incidente: texto(),
    resultado: umDe(RESULTADOS_DO_EFEITO),
    observacao: textoLongo,
  }),
  Promocao: objeto({ proposta: texto(), acao: AcaoDoCatalogo }),
  Recusa: objeto({
    agente: ouNulo(umDe(AGENTES)),
    tool: texto(),
    argumentos: livre,
    motivo: umDe(MOTIVOS_DE_RECUSA),
    mensagem: textoLongo,
  }),
};

/** A definição do contrato que vai em `dados`, para cada tipo de evento. */
export const DADOS_DO_TIPO = new Map<TipoDeEvento, string>([
  ["janelas_classificadas", "LoteDeJanelas"],
  ["incidente_aberto", "Incidente"],
  ["incidente_atualizado", "Incidente"],
  ["incidente_encerrado", "Incidente"],
  ["incidente_marcado_resolvido", "MarcaDeResolvido"],
  ["llm_chamada", "ChamadaDeLLM"],
  ["tool_chamada", "ChamadaDeTool"],
  ["agente_concluido", "ConclusaoDoAgente"],
  ["atacante_apontado", "AtacanteApontado"],
  ["analise_emitida", "AnaliseDaTriagem"],
  ["recomendacao_emitida", "Recomendacao"],
  ["sumario_emitido", "Sumario"],
  ["acao_proposta", "Proposta"],
  ["acao_aprovada", "Decisao"],
  ["acao_rejeitada", "Decisao"],
  ["acao_executada", "Execucao"],
  ["acao_desfeita", "Execucao"],
  ["efeito_verificado", "Efeito"],
  ["catalogo_ampliado", "Promocao"],
  ["recusa", "Recusa"],
]);

const ESTADO_DO_TIPO = new Map<string, string>([
  ["incidente_aberto", "aberto"],
  ["incidente_atualizado", "aberto"],
  ["incidente_encerrado", "encerrado"],
]);

export type Conferido = { evento: Evento; problema?: undefined } | { evento?: undefined; problema: string };

/**
 * Confere um valor lido de uma linha do log. Devolve o evento, já com o tipo certo, ou o problema
 * em poucas palavras. O problema cita só nomes de campo e o tipo do evento, nunca o valor lido.
 */
export function conferirEvento(valor: unknown): Conferido {
  if (!ehObjeto(valor)) {
    return { problema: "não é um objeto JSON" };
  }
  const tipo = valor.tipo;
  const definicao = typeof tipo === "string" ? DADOS_DO_TIPO.get(tipo as TipoDeEvento) : undefined;
  if (typeof tipo !== "string" || !definicao) {
    return { problema: "tipo de evento desconhecido" };
  }
  const problema =
    texto()(valor.id, "id") ??
    instante(valor.instante, "instante") ??
    (temCampo(valor, "incidente") ? ouNulo(texto())(valor.incidente, "incidente") : "incidente") ??
    (temCampo(valor, "dados") ? DEFINICOES[definicao](valor.dados, "dados") : "dados");
  if (problema) {
    return { problema: `${tipo} com ${problema} fora do contrato` };
  }
  const dados = valor.dados as Record<string, unknown>;
  // O estado vem inteiro em cada evento de incidente: ele só vale para o incidente do próprio evento.
  const estadoEsperado = ESTADO_DO_TIPO.get(tipo);
  if (estadoEsperado !== undefined) {
    if (dados.id !== valor.incidente) {
      return { problema: `${tipo} com dados.id diferente do campo incidente` };
    }
    if (dados.estado !== estadoEsperado) {
      return { problema: `${tipo} com o estado ${String(dados.estado)}` };
    }
    // A regra das origens só separa DDoS de DoS; as outras categorias são as do modelo.
    const possiveis = dados.categoria_do_modelo === "DDoS+DoS" ? ["DDoS", "DoS"] : [dados.categoria_do_modelo];
    if (!possiveis.includes(dados.categoria)) {
      return { problema: `${tipo} com dados.categoria que não sai de dados.categoria_do_modelo` };
    }
  }
  if (tipo === "incidente_marcado_resolvido" && dados.incidente !== valor.incidente) {
    return { problema: `${tipo} com dados.incidente diferente do campo incidente` };
  }
  // Como em `ConclusaoDoAgente`, de `tipos.py`: só a triagem dá veredito.
  if (tipo === "agente_concluido" && dados.veredito !== null && dados.agente !== "triagem") {
    return { problema: `${tipo} com dados.veredito de um agente que não é a triagem` };
  }
  return { evento: valor as unknown as Evento };
}
