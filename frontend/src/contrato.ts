import type { Evento, TipoDeEvento } from "./types";

// Conferência de cada linha do log contra o contrato (`codigo/mcp/contrato.json`). Cobre os
// campos obrigatórios, os tipos, os valores aceitos e os limites de texto de cada tipo de evento.
// Campo a mais não derruba a linha: o contrato pode ganhar campos antes de a interface ser
// atualizada, e o que a interface não lê não muda a tela.

export const CATEGORIAS = [
  "DDoS",
  "DoS",
  "Mirai",
  "Recon",
  "Spoofing",
  "Web",
  "BruteForce",
  "Benign",
] as const;
const AGENTES = ["triagem", "decisao", "execucao"] as const;
const CANAIS = ["terminal", "interface"] as const;
const CODIGOS_DE_RISCO_ALTO = [
  "acao_sempre_de_risco_alto",
  "acao_nova",
  "prazo_acima_do_limite",
  "alvo_fora_do_incidente",
  "alvo_e_destino_do_incidente",
  "alvo_protegido",
  "orcamento_de_risco_baixo_esgotado",
] as const;
const MOTIVOS_DE_RECUSA = [
  "identificador_desconhecido",
  "argumentos_invalidos",
  "alvo_malformado",
  "alvo_nao_permitido",
  "incidente_encerrado",
  "limite_de_propostas_pendentes",
  "acao_nova_incompleta",
  "proposta_nao_liberada",
  "proposta_ja_executada",
  "acao_nao_aplicada",
  "tool_fora_da_linha",
] as const;

// Os mesmos limites e padrões de `tipos.py`.
const TEXTO_CURTO = 200;
const TEXTO_LONGO = 2_000;
const MAXIMO_DE_PASSOS = 20;
const MAXIMO_DE_PROPOSTAS_POR_RECOMENDACAO = 20;
const UMA_LINHA = /^[^\x00-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]*$/;
const PARAGRAFOS = /^[^\x00-\x09\x0b-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]*$/;
const NOME_DE_ACAO = /^[a-z][a-z0-9_]{0,59}$/;
// O instante sai do Python como `2026-10-20T14:03:41.004000Z`: data e hora com fuso, sempre.
const INSTANTE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/** Devolve onde está o primeiro problema (`dados.janelas`, por exemplo), ou null se o valor serve. */
type Regra = (valor: unknown, caminho: string) => string | null;

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

function texto(maximo = TEXTO_CURTO, padrao = UMA_LINHA): Regra {
  return (valor, caminho) => {
    if (typeof valor !== "string" || !padrao.test(valor)) {
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
const booleano: Regra = (valor, caminho) => (typeof valor === "boolean" ? null : caminho);
const instante: Regra = (valor, caminho) =>
  typeof valor === "string" && Number.isFinite(instanteEmMs(valor)) ? null : caminho;
const livre: Regra = (valor, caminho) => (ehObjeto(valor) ? null : caminho);
const nomeDeAcao = texto(60, NOME_DE_ACAO);
const textoLongo = texto(TEXTO_LONGO);

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

/** Objeto com os campos obrigatórios `campos`. */
function objeto(campos: Record<string, Regra>): Regra {
  return (valor, caminho) => {
    if (!ehObjeto(valor)) {
      return caminho;
    }
    for (const [nome, regra] of Object.entries(campos)) {
      if (!temCampo(valor, nome)) {
        return `${caminho}.${nome}`;
      }
      const problema = regra(valor[nome], `${caminho}.${nome}`);
      if (problema) {
        return problema;
      }
    }
    return null;
  };
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

const enderecoContado = objeto({ endereco: texto(45), quadros: contagem });
const incidente = objeto({
  id: texto(),
  estado: umDe(["aberto", "encerrado"]),
  categoria: umDe(CATEGORIAS),
  categoria_do_modelo: umDe(CATEGORIAS),
  confianca: numero(0, 1),
  inicio: instante,
  fim: instante,
  janelas: inteiro(1),
  origens_distintas: contagem,
  distribuido: booleano,
  origens: lista(enderecoContado),
  destinos: lista(enderecoContado),
  features_principais: lista(objeto({ nome: texto(), valor: numero(), referencia_benigno: numero() })),
});
const execucao = objeto({
  id: texto(),
  proposta: texto(),
  incidente: texto(),
  acao: nomeDeAcao,
  alvo: texto(),
  parametros: livre,
  estado: umDe(["aplicada", "desfeita"]),
  aplicada_em: instante,
  desfeita_em: ouNulo(instante),
});
const acaoDoCatalogo = objeto({
  nome: nomeDeAcao,
  descricao: textoLongo,
  alvo: textoLongo,
  parametros: lista(objeto({ nome: texto(), descricao: textoLongo, obrigatorio: booleano })),
  regra: textoLongo,
  origem: umDe(["base", "promovida"]),
  passos: lista(textoLongo, MAXIMO_DE_PASSOS),
  efeito_esperado: ouNulo(textoLongo),
  como_desfazer: textoLongo,
  fonte: ouNulo(texto()),
});

const DADOS_DO_TIPO = new Map<TipoDeEvento, Regra>([
  ["janelas_classificadas", objeto({ janelas: contagem, por_categoria: mapa(umDe(CATEGORIAS), contagem) })],
  ["incidente_aberto", incidente],
  ["incidente_atualizado", incidente],
  ["incidente_encerrado", incidente],
  [
    "llm_chamada",
    objeto({
      agente: umDe(AGENTES),
      modelo: texto(),
      tokens_entrada: contagem,
      tokens_saida: contagem,
      duracao_ms: numero(0),
    }),
  ],
  [
    "tool_chamada",
    objeto({ agente: ouNulo(umDe(AGENTES)), nome: texto(), argumentos: livre, resultado: livre, duracao_ms: numero(0) }),
  ],
  [
    "recomendacao_emitida",
    objeto({
      agente: umDe(AGENTES),
      texto: texto(TEXTO_LONGO, PARAGRAFOS),
      propostas: lista(texto(), MAXIMO_DE_PROPOSTAS_POR_RECOMENDACAO),
    }),
  ],
  [
    "acao_proposta",
    objeto({
      id: texto(),
      incidente: texto(),
      acao: nomeDeAcao,
      alvo: texto(),
      parametros: livre,
      justificativa: textoLongo,
      nova: booleano,
      risco: umDe(["baixo", "alto"]),
      motivos_de_risco_alto: lista(
        objeto({ codigo: umDe(CODIGOS_DE_RISCO_ALTO), descricao: textoLongo }),
        CODIGOS_DE_RISCO_ALTO.length,
      ),
      exige_aprovacao: booleano,
      estado: umDe(["aguardando_aprovacao", "liberada", "rejeitada", "executada", "desfeita"]),
    }),
  ],
  ["acao_aprovada", objeto({ proposta: texto(), canal: umDe(CANAIS), motivo: ouNulo(textoLongo) })],
  ["acao_rejeitada", objeto({ proposta: texto(), canal: umDe(CANAIS), motivo: ouNulo(textoLongo) })],
  ["acao_executada", execucao],
  ["acao_desfeita", execucao],
  [
    "efeito_verificado",
    objeto({
      execucao: texto(),
      incidente: texto(),
      resultado: umDe(["cessou", "diminuiu", "persiste"]),
      observacao: textoLongo,
    }),
  ],
  ["catalogo_ampliado", objeto({ proposta: texto(), acao: acaoDoCatalogo })],
  [
    "recusa",
    objeto({
      agente: ouNulo(umDe(AGENTES)),
      tool: texto(),
      argumentos: livre,
      motivo: umDe(MOTIVOS_DE_RECUSA),
      mensagem: textoLongo,
    }),
  ],
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
  const regra = typeof tipo === "string" ? DADOS_DO_TIPO.get(tipo as TipoDeEvento) : undefined;
  if (typeof tipo !== "string" || !regra) {
    return { problema: "tipo de evento desconhecido" };
  }
  const problema =
    texto()(valor.id, "id") ??
    instante(valor.instante, "instante") ??
    (temCampo(valor, "incidente") ? ouNulo(texto())(valor.incidente, "incidente") : "incidente") ??
    (temCampo(valor, "dados") ? regra(valor.dados, "dados") : "dados");
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
  }
  return { evento: valor as unknown as Evento };
}
