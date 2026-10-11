import { conferirEvento } from "./contrato";
import { ACOES_DE_BASE, MOTIVOS_DE_RISCO_ALTO, SEMPRE_DE_RISCO_ALTO } from "./listas";
import type {
  Evento,
  Execucao,
  ExecucaoView,
  Incidente,
  IncidenteView,
  MarcaDeResolvido,
  PropostaView,
  ResumoGeral,
} from "./types";

// O log de exemplo, servido de `public/dados/`. O BASE_URL mantém o caminho certo quando o app é
// servido em um subcaminho.
export const CAMINHO_DO_LOG = `${import.meta.env.BASE_URL}dados/incidente_flood.jsonl`;
// Quantas linhas ou eventos um aviso cita antes de resumir o resto.
const CITADOS_POR_AVISO = 8;
// Um valor que veio do log aparece nos avisos entre aspas e cortado: é dado, e não texto do sistema.
const MAIOR_CITACAO = 40;

export function citar(valor: string): string {
  const letras = Array.from(valor);
  return `“${letras.length > MAIOR_CITACAO ? `${letras.slice(0, MAIOR_CITACAO).join("")}…` : valor}”`;
}

export interface LogLido {
  /** Eventos válidos, sem repetição, na ordem do `id`. */
  eventos: Evento[];
  /** O que foi descartado ou reordenado na leitura, para mostrar na tela. */
  avisos: string[];
}

export interface OpcoesDeLeitura {
  /**
   * Ignora a última linha quando ela não termina em quebra de linha. Serve para o modo ao vivo, em
   * que essa linha pode estar sendo gravada. No replay, o arquivo está completo e a linha é lida,
   * como faz o leitor do Python.
   */
  ignorarUltimaIncompleta?: boolean;
}

function citarLista(itens: string[]): string {
  const citados = itens.slice(0, CITADOS_POR_AVISO).join(", ");
  return itens.length > CITADOS_POR_AVISO ? `${citados} e mais ${itens.length - CITADOS_POR_AVISO}` : citados;
}

/**
 * Posição do evento na sequência do log: o número no fim do `id` (`ev-000012` dá 12). Um id sem
 * número vai para o fim, na ordem do arquivo.
 */
function posicaoDoId(id: string): number {
  const achado = /(\d+)$/.exec(id);
  return achado ? Number(achado[1]) : Number.POSITIVE_INFINITY;
}

/**
 * Lê o texto do log (uma linha, um evento). Cada linha é conferida contra o contrato, e a que não
 * serve é descartada, com o número dela num aviso: uma linha ruim não derruba a tela. Evento com
 * `id` repetido fica só na primeira vez em que aparece. Os eventos voltam em ordem de `id`, que é a
 * ordem em que foram gravados, e não a das linhas do arquivo.
 */
export function lerLog(texto: string, opcoes: OpcoesDeLeitura = {}): LogLido {
  const linhas = texto.split("\n");
  const avisos: string[] = [];
  const ultima = linhas[linhas.length - 1];
  if (ultima.trim().length > 0 && opcoes.ignorarUltimaIncompleta) {
    linhas.pop();
    avisos.push(`A linha ${linhas.length + 1} não termina em quebra de linha e foi ignorada: pode estar sendo gravada.`);
  }

  const descartadas: string[] = [];
  const repetidas: string[] = [];
  const vistos = new Set<string>();
  const lidos: Evento[] = [];
  linhas.forEach((linha, indice) => {
    if (linha.trim().length === 0) {
      return;
    }
    const numero = indice + 1;
    let valor: unknown;
    try {
      valor = JSON.parse(linha);
    } catch {
      descartadas.push(`${numero} (não é um JSON válido)`);
      return;
    }
    const conferido = conferirEvento(valor);
    if (!conferido.evento) {
      descartadas.push(`${numero} (${conferido.problema})`);
      return;
    }
    if (vistos.has(conferido.evento.id)) {
      repetidas.push(String(numero));
      return;
    }
    vistos.add(conferido.evento.id);
    lidos.push(conferido.evento);
  });

  if (descartadas.length > 0) {
    avisos.push(`Linhas fora do contrato, descartadas: ${citarLista(descartadas).replace(/\), /g, "); ")}.`);
  }
  if (repetidas.length > 0) {
    avisos.push(`Linhas com id de evento repetido, descartadas: ${citarLista(repetidas)}.`);
  }

  // O sort é estável: eventos com a mesma posição ficam na ordem do arquivo.
  const eventos = [...lidos].sort((a, b) => posicaoDoId(a.id) - posicaoDoId(b.id));
  if (eventos.some((evento, indice) => evento !== lidos[indice])) {
    avisos.push("Os eventos não estão em ordem no arquivo. A tela usa a ordem dos ids.");
  }
  return { eventos, avisos };
}

/** Busca o log no caminho estático servido pelo Vite e o lê com `lerLog`. */
export async function carregarLog(caminho = CAMINHO_DO_LOG, opcoes: OpcoesDeLeitura = {}): Promise<LogLido> {
  const resposta = await fetch(caminho);
  if (!resposta.ok) {
    throw new Error(
      `não foi possível carregar o log em ${caminho} (HTTP ${resposta.status}). ` +
        "Confira se public/dados/incidente_flood.jsonl existe (npm run sync:log copia o exemplo de codigo/mcp/exemplos/).",
    );
  }
  return lerLog(await resposta.text(), opcoes);
}

export interface Agregado {
  resumo: ResumoGeral;
  incidentes: IncidenteView[];
  /** Eventos que não cabem no ponto em que aparecem (aprovar proposta que não existe, por exemplo). */
  avisos: string[];
}

// --- Reconstrução do estado ----------------------------------------------------------------

const BASE = new Set<string>(ACOES_DE_BASE);
const SEMPRE_ALTO = new Set<string>(SEMPRE_DE_RISCO_ALTO);
// O alvo com rótulo neutro: `origem-1`, `destino-2` ou `conta@destino-1` (`_ALVO_COM_ROTULO`, em acoes.py).
export const ALVO_COM_ROTULO = /^(?:[A-Za-z0-9_][A-Za-z0-9._-]{0,63}@)?(?:origem|destino)-[1-9][0-9]{0,5}$/;
const PAPEIS = [
  ["origem", "origens"],
  ["destino", "destinos"],
] as const;

/** O estado que os eventos deixam, como o `Estado` de `codigo/mcp/acoes.py`, mais o que a tela mostra. */
interface Estado {
  incidentes: Map<string, Incidente>;
  /** Para cada incidente, o endereço de cada rótulo neutro (origem-1, destino-1). */
  rotulos: Map<string, Map<string, string>>;
  resolvidos: Map<string, MarcaDeResolvido>;
  propostas: Map<string, { incidente: string; parametros: unknown; view: PropostaView }>;
  execucoes: Map<string, { dados: Execucao; view: ExecucaoView }>;
  promovidas: Set<string>;
}

/** Igualdade de valores JSON, sem depender da ordem das chaves. */
function iguais(a: unknown, b: unknown): boolean {
  if (a === b) {
    return true;
  }
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null || Array.isArray(a) !== Array.isArray(b)) {
    return false;
  }
  const chavesA = Object.keys(a);
  const chavesB = Object.keys(b);
  return (
    chavesA.length === chavesB.length &&
    chavesA.every((chave) => Object.prototype.hasOwnProperty.call(b, chave) && iguais((a as Record<string, unknown>)[chave], (b as Record<string, unknown>)[chave]))
  );
}

/** Dá um rótulo neutro a cada endereço novo do incidente, na ordem em que ele aparece (`_rotular`). */
function rotular(estado: Estado, incidente: Incidente) {
  let rotulos = estado.rotulos.get(incidente.id);
  if (!rotulos) {
    rotulos = new Map();
    estado.rotulos.set(incidente.id, rotulos);
  }
  for (const [papel, campo] of PAPEIS) {
    const doPapel = Array.from(rotulos).filter(([rotulo]) => rotulo.startsWith(`${papel}-`)).map(([, endereco]) => endereco);
    for (const item of incidente[campo]) {
      if (!doPapel.includes(item.endereco)) {
        doPapel.push(item.endereco);
        rotulos.set(`${papel}-${doPapel.length}`, item.endereco);
      }
    }
  }
}

/** O alvo com o rótulo trocado pelo endereço, ou null se o rótulo não existe no incidente. */
function resolverRotulo(estado: Estado, incidente: string, alvo: string): string | null {
  const arroba = alvo.lastIndexOf("@");
  const endereco = estado.rotulos.get(incidente)?.get(alvo.slice(arroba + 1));
  return endereco === undefined ? null : `${alvo.slice(0, arroba + 1)}${endereco}`;
}

/**
 * Confere se o evento cabe no estado e, se couber, aplica o que ele diz. Devolve o problema, ou
 * null. As regras são as de `_aplicar`, em `codigo/mcp/acoes.py`; o que fica de fora está no
 * README do frontend. Um evento que não cabe não muda nada.
 */
function aplicar(estado: Estado, evento: Evento): string | null {
  switch (evento.tipo) {
    case "incidente_aberto": {
      const dados = evento.dados;
      if (estado.incidentes.has(dados.id)) {
        return `o incidente ${citar(dados.id)} já foi aberto`;
      }
      estado.incidentes.set(dados.id, dados);
      rotular(estado, dados);
      return null;
    }
    case "incidente_atualizado":
    case "incidente_encerrado": {
      const dados = evento.dados;
      const atual = estado.incidentes.get(dados.id);
      if (!atual) {
        return `o incidente ${citar(dados.id)} não foi aberto até este ponto`;
      }
      if (atual.estado !== "aberto") {
        return `o incidente ${citar(dados.id)} já está encerrado`;
      }
      estado.incidentes.set(dados.id, dados);
      rotular(estado, dados);
      return null;
    }
    case "incidente_marcado_resolvido": {
      const dados = evento.dados;
      if (!estado.incidentes.has(dados.incidente)) {
        return `o incidente ${citar(dados.incidente)} não existe até este ponto`;
      }
      if (estado.resolvidos.has(dados.incidente)) {
        return `o incidente ${citar(dados.incidente)} já foi marcado como resolvido`;
      }
      estado.resolvidos.set(dados.incidente, dados);
      return null;
    }
    case "acao_proposta":
      return aplicarProposta(estado, evento);
    case "acao_aprovada":
    case "acao_rejeitada": {
      const dados = evento.dados;
      const proposta = estado.propostas.get(dados.proposta);
      if (!proposta) {
        return `a proposta ${citar(dados.proposta)} não existe até este ponto`;
      }
      if (evento.incidente !== proposta.incidente) {
        return `a proposta ${citar(dados.proposta)} é de outro incidente`;
      }
      if (proposta.view.estado !== "aguardando_aprovacao") {
        return `a proposta ${citar(dados.proposta)} não aguarda aprovação (está ${proposta.view.estado})`;
      }
      proposta.view.estado = evento.tipo === "acao_aprovada" ? "liberada" : "rejeitada";
      proposta.view.decisoes.push({
        tipo: evento.tipo,
        instante: evento.instante,
        canal: dados.canal,
        usuario: dados.usuario,
        motivo: dados.motivo,
      });
      return null;
    }
    case "acao_executada": {
      const dados = evento.dados;
      const proposta = estado.propostas.get(dados.proposta);
      if (!proposta) {
        return `a proposta ${citar(dados.proposta)} não existe até este ponto`;
      }
      if (estado.execucoes.has(dados.id)) {
        return `a execução ${citar(dados.id)} já existe`;
      }
      if (proposta.view.estado !== "liberada") {
        return `a proposta ${citar(dados.proposta)} não está liberada nem aprovada (está ${proposta.view.estado})`;
      }
      if (estado.resolvidos.has(proposta.incidente)) {
        return `o incidente ${citar(proposta.incidente)} foi marcado como já resolvido, e nenhuma ação é aplicada nele`;
      }
      if (
        dados.incidente !== proposta.incidente ||
        dados.acao !== proposta.view.acao ||
        dados.alvo !== proposta.view.alvo ||
        !iguais(dados.parametros, proposta.parametros) ||
        dados.estado !== "aplicada"
      ) {
        return `a execução ${citar(dados.id)} não é a aplicação do que a proposta ${citar(dados.proposta)} descreve`;
      }
      const view: ExecucaoView = { id: dados.id, estado: "aplicada", aplicadaEm: dados.aplicada_em, desfeitaEm: null, efeitos: [] };
      estado.execucoes.set(dados.id, { dados, view });
      proposta.view.execucoes.push(view);
      proposta.view.estado = "executada";
      return null;
    }
    case "acao_desfeita": {
      const dados = evento.dados;
      const aplicada = estado.execucoes.get(dados.id);
      if (!aplicada) {
        return `a execução ${citar(dados.id)} não existe até este ponto`;
      }
      if (aplicada.dados.estado !== "aplicada") {
        return `a execução ${citar(dados.id)} já foi desfeita`;
      }
      if (dados.desfeita_em === null || !iguais(dados, { ...aplicada.dados, estado: "desfeita", desfeita_em: dados.desfeita_em })) {
        return `a execução ${citar(dados.id)} desfeita não é a mesma que foi aplicada`;
      }
      aplicada.dados = dados;
      aplicada.view.estado = "desfeita";
      aplicada.view.desfeitaEm = dados.desfeita_em;
      const proposta = estado.propostas.get(dados.proposta);
      if (proposta) {
        proposta.view.estado = "desfeita";
      }
      return null;
    }
    case "efeito_verificado": {
      const dados = evento.dados;
      const execucao = estado.execucoes.get(dados.execucao);
      if (!execucao) {
        return `a execução ${citar(dados.execucao)} não existe até este ponto`;
      }
      if (dados.incidente !== execucao.dados.incidente) {
        return `o efeito é de outro incidente que o da execução ${citar(dados.execucao)}`;
      }
      execucao.view.efeitos.push({ instante: evento.instante, resultado: dados.resultado, observacao: dados.observacao });
      return null;
    }
    case "recomendacao_emitida":
      for (const citada of evento.dados.propostas) {
        const proposta = estado.propostas.get(citada);
        if (!proposta) {
          return `cita a proposta ${citar(citada)}, que não existe até este ponto`;
        }
        if (proposta.incidente !== evento.incidente) {
          return `cita a proposta ${citar(citada)}, que é de outro incidente`;
        }
      }
      return null;
    case "catalogo_ampliado": {
      const dados = evento.dados;
      const proposta = estado.propostas.get(dados.proposta);
      if (!proposta) {
        return `a proposta ${citar(dados.proposta)} não existe até este ponto`;
      }
      if (evento.incidente !== proposta.incidente) {
        return `a proposta ${citar(dados.proposta)} é de outro incidente`;
      }
      const nome = dados.acao.nome;
      if (BASE.has(nome) || estado.promovidas.has(nome)) {
        return `a ação ${citar(nome)} já está no catálogo`;
      }
      const view = proposta.view;
      if (!view.nova || view.estado !== "executada" || nome !== view.acao || dados.acao.origem !== "promovida") {
        return `a proposta ${citar(dados.proposta)} não é de uma ação nova aplicada, com o mesmo nome`;
      }
      estado.promovidas.add(nome);
      view.promovida = true;
      return null;
    }
    default:
      return null;
  }
}

/** Uma proposta só entra no estado como o servidor a teria criado (`_conferir_proposta_nova`). */
function aplicarProposta(estado: Estado, evento: Extract<Evento, { tipo: "acao_proposta" }>): string | null {
  const dados = evento.dados;
  const id = citar(dados.id);
  if (estado.propostas.has(dados.id)) {
    return `a proposta ${id} já existe`;
  }
  if (!estado.incidentes.has(dados.incidente)) {
    return `a proposta ${id} cita um incidente que não existe até este ponto`;
  }
  if (estado.resolvidos.has(dados.incidente)) {
    return `a proposta ${id} é de incidente marcado como já resolvido, que não recebe proposta`;
  }
  const deRiscoAlto = dados.risco === "alto";
  if (dados.exige_aprovacao !== deRiscoAlto) {
    return `a proposta ${id} tem risco ${dados.risco} e exige_aprovacao ${dados.exige_aprovacao}`;
  }
  const inicial = deRiscoAlto ? "aguardando_aprovacao" : "liberada";
  if (dados.estado !== inicial) {
    return `a proposta ${id}, de risco ${dados.risco}, nasce como ${inicial}, e não como ${dados.estado}`;
  }
  if (!deRiscoAlto && (!BASE.has(dados.acao) || SEMPRE_ALTO.has(dados.acao))) {
    return `a proposta ${id} vem como de risco baixo, e a ação dela é sempre de risco alto`;
  }
  if (dados.nova !== (!BASE.has(dados.acao) && !estado.promovidas.has(dados.acao))) {
    return `a proposta ${id} vem com nova = ${dados.nova}, o que não confere com o catálogo`;
  }
  if (
    dados.alvo_com_rotulo !== null &&
    (!ALVO_COM_ROTULO.test(dados.alvo_com_rotulo) || resolverRotulo(estado, dados.incidente, dados.alvo_com_rotulo) !== dados.alvo)
  ) {
    return `a proposta ${id} traz um rótulo que não dá o alvo dela no incidente`;
  }
  // Os motivos são texto do sistema na tela de aprovação: existem se e só se o risco é alto, não se
  // repetem e trazem a frase do contrato, e não outra.
  const codigos = dados.motivos_de_risco_alto.map((motivo) => motivo.codigo);
  if ((codigos.length > 0) !== deRiscoAlto) {
    return `a proposta ${id} é de risco ${dados.risco} e ${codigos.length > 0 ? "traz" : "não traz"} motivo de risco alto`;
  }
  if (new Set(codigos).size !== codigos.length) {
    return `a proposta ${id} repete um motivo de risco alto`;
  }
  if (dados.motivos_de_risco_alto.some((motivo) => motivo.descricao !== MOTIVOS_DE_RISCO_ALTO[motivo.codigo])) {
    return `a proposta ${id} traz um motivo de risco alto com uma frase que não é a do contrato`;
  }
  estado.propostas.set(dados.id, {
    incidente: dados.incidente,
    parametros: dados.parametros,
    view: {
      id: dados.id,
      acao: dados.acao,
      alvo: dados.alvo,
      alvoComRotulo: dados.alvo_com_rotulo,
      justificativa: dados.justificativa,
      nova: dados.nova,
      risco: dados.risco,
      exigeAprovacao: dados.exige_aprovacao,
      motivosDeRiscoAlto: codigos,
      estado: inicial,
      criadaEm: evento.instante,
      decisoes: [],
      execucoes: [],
      promovida: false,
    },
  });
  return null;
}

interface Montagem extends Omit<IncidenteView, "incidente"> {
  incidente: Incidente;
}

/**
 * Reconstrói o estado com as regras do `reconstruir` de `codigo/mcp/acoes.py`, agrupa os eventos
 * por incidente e soma os contadores globais. Espera os eventos na ordem do `id`, como saem de
 * `lerLog`.
 *
 * O Python recusa o log inteiro no primeiro evento fora de lugar. A interface mostra o que dá: o
 * evento que não cabe no estado em que aparece não muda nada, não entra no histórico e gera um
 * aviso com o id dele. Um evento cujo incidente não estava aberto naquele ponto fica fora da fila,
 * contado à parte. As regras de estado valem para todo evento; o campo `incidente` só diz em que
 * linha da fila ele aparece.
 */
export function agregar(eventos: Evento[]): Agregado {
  const avisos: string[] = [];
  const estado: Estado = {
    incidentes: new Map(),
    rotulos: new Map(),
    resolvidos: new Map(),
    propostas: new Map(),
    execucoes: new Map(),
    promovidas: new Set(),
  };
  const montagens = new Map<string, Montagem>();
  const semAbertura = new Map<string, string[]>();
  let janelasClassificadas = 0;
  let chamadasLLM = 0;
  let tokens = 0;

  for (const evento of eventos) {
    if (evento.tipo === "janelas_classificadas") {
      janelasClassificadas += evento.dados.janelas;
    }
    if (evento.tipo === "llm_chamada") {
      // Contadas aqui, e não por incidente, para que chamadas e tokens do resumo sejam sempre
      // do mesmo conjunto de eventos, mesmo que uma chamada venha sem incidente.
      chamadasLLM += 1;
      tokens += evento.dados.tokens_entrada + evento.dados.tokens_saida;
    }

    const problema = aplicar(estado, evento);
    if (problema) {
      avisos.push(`Evento ${citar(evento.id)} (${evento.tipo}) ignorado: ${problema}.`);
      continue;
    }
    if (evento.incidente === null) {
      continue;
    }
    const incidente = estado.incidentes.get(evento.incidente);
    if (!incidente) {
      semAbertura.set(evento.incidente, [...(semAbertura.get(evento.incidente) ?? []), evento.id]);
      continue;
    }

    let montagem = montagens.get(evento.incidente);
    if (!montagem) {
      montagem = {
        id: evento.incidente,
        incidente,
        abertoEm: evento.instante,
        eventos: [],
        chamadasLLM: 0,
        tokensEntrada: 0,
        tokensSaida: 0,
        recomendacoes: [],
        propostas: [],
        marcacao: null,
      };
      montagens.set(evento.incidente, montagem);
    }
    montagem.incidente = incidente;
    montagem.eventos.push(evento);
    switch (evento.tipo) {
      case "llm_chamada":
        montagem.chamadasLLM += 1;
        montagem.tokensEntrada += evento.dados.tokens_entrada;
        montagem.tokensSaida += evento.dados.tokens_saida;
        break;
      case "recomendacao_emitida":
        montagem.recomendacoes.push(evento);
        break;
      case "acao_proposta":
        montagem.propostas.push(estado.propostas.get(evento.dados.id)!.view);
        break;
      case "incidente_marcado_resolvido":
        montagem.marcacao = {
          instante: evento.instante,
          canal: evento.dados.canal,
          usuario: evento.dados.usuario,
          motivo: evento.dados.motivo,
        };
        break;
      default:
        break;
    }
  }

  const eventosSemAbertura = Array.from(semAbertura.values()).flat();
  const incidentesSemAbertura = Array.from(semAbertura.keys());
  if (eventosSemAbertura.length > 0) {
    avisos.push(
      `${eventosSemAbertura.length} evento(s) citam incidente que não estava aberto naquele ponto do log ` +
        `(${citarLista(incidentesSemAbertura.map(citar))}; eventos ${citarLista(eventosSemAbertura.map(citar))}). ` +
        "Ficam fora da fila e não contam como incidente.",
    );
  }

  const incidentes = Array.from(montagens.values());
  return {
    resumo: {
      janelasClassificadas,
      totalIncidentes: incidentes.length,
      chamadasLLM,
      tokens,
      eventosSemAbertura: eventosSemAbertura.length,
      incidentesSemAbertura,
    },
    incidentes,
    avisos,
  };
}
