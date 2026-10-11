import { Fragment, useState } from "react";
import { inteiro, numero } from "../formato";
import { MOTIVOS_DE_RISCO_ALTO } from "../listas";
import {
  ESTADO_DA_PROPOSTA,
  MOTIVO_DA_RECUSA,
  NOME_DO_AGENTE,
  PELO_CANAL,
  RESULTADO_DO_EFEITO,
  ROTULO_DO_EVENTO,
  alvoNaTela,
  aspas,
  rotulo,
} from "../rotulos";
import type { Agente, Canal, Evento, EventoDeLLM, EventoDeRecusa, EventoDeTool, IncidenteView, PropostaView, TipoDeEvento } from "../types";
import Instante from "./Instante";

interface Props {
  incidente: IncidenteView;
}

// Os eventos que entram no histórico de decisões e ações.
const EVENTOS_DO_HISTORICO = new Set<TipoDeEvento>([
  "acao_proposta",
  "acao_aprovada",
  "acao_rejeitada",
  "acao_executada",
  "acao_desfeita",
  "efeito_verificado",
  "catalogo_ampliado",
  "recusa",
  "incidente_marcado_resolvido",
]);
const RASTRO_RESUMIDO = 7;

function nomeDoAgente(agente: Agente | null): string {
  // `agente` é nulo na tool_chamada quando o stub sobe com `--agente todos`.
  return agente === null ? "Agente não identificado" : rotulo(NOME_DO_AGENTE, agente);
}

/** A proposta ou a execução de que a recusa fala, quando os argumentos da tool dizem; senão, o id do evento. */
function idDaRecusa(evento: EventoDeRecusa): string {
  const citado = evento.dados.argumentos.id_proposta ?? evento.dados.argumentos.id_execucao;
  return typeof citado === "string" ? citado : evento.id;
}

/** Quem decidiu e por qual canal, com o motivo da pessoa entre aspas. */
function quemDecidiu(canal: Canal, usuario: string, motivo: string | null): string {
  return `${rotulo(PELO_CANAL, canal)}, por ${usuario}${motivo ? `: ${aspas(motivo)}` : ""}`;
}

// Cada linha do histórico diz de qual proposta ou execução está falando (o id), e o que aconteceu.
// O que cada tipo traz em `dados` está na tabela do log em codigo/mcp/README.md. Texto escrito por
// um agente ou por uma pessoa vai entre aspas.
function linhaDoHistorico(evento: Evento): { id: string; descricao: string } | null {
  switch (evento.tipo) {
    case "acao_proposta": {
      const { dados } = evento;
      const aprovacao = dados.exige_aprovacao ? "exige aprovação" : "sem aprovação";
      return {
        id: dados.id,
        descricao: `${dados.acao} em ${alvoNaTela(dados.alvo, dados.alvo_com_rotulo)} · risco ${dados.risco}, ${aprovacao}`,
      };
    }
    case "acao_aprovada":
    case "acao_rejeitada": {
      const { dados } = evento;
      return { id: dados.proposta, descricao: quemDecidiu(dados.canal, dados.usuario, dados.motivo) };
    }
    case "acao_executada":
    case "acao_desfeita":
      return { id: evento.dados.id, descricao: `${evento.dados.acao} em ${evento.dados.alvo} · proposta ${evento.dados.proposta}` };
    case "efeito_verificado":
      return {
        id: evento.dados.execucao,
        descricao: `${rotulo(RESULTADO_DO_EFEITO, evento.dados.resultado)} · ${evento.dados.observacao}`,
      };
    case "catalogo_ampliado":
      return { id: evento.dados.proposta, descricao: `a ação ${evento.dados.acao.nome} entra no catálogo` };
    case "recusa":
      return {
        id: idDaRecusa(evento),
        descricao: `${evento.dados.tool} · ${rotulo(MOTIVO_DA_RECUSA, evento.dados.motivo)} · ${aspas(evento.dados.mensagem)}`,
      };
    case "incidente_marcado_resolvido": {
      const { dados } = evento;
      return { id: dados.incidente, descricao: quemDecidiu(dados.canal, dados.usuario, dados.motivo) };
    }
    default:
      return null;
  }
}

function CartaoDaProposta({ proposta }: { proposta: PropostaView }) {
  return (
    <li className="proposal">
      <div className="proposal-head">
        <code className="event-id">{proposta.id}</code>
        <strong>{proposta.acao}</strong>
        <span className="proposal-target">em {alvoNaTela(proposta.alvo, proposta.alvoComRotulo)}</span>
        <span className={`proposal-state proposal-${proposta.estado}`}>{rotulo(ESTADO_DA_PROPOSTA, proposta.estado)}</span>
      </div>
      <div className="proposal-meta">
        <span className={`risk risk-${proposta.risco}`}>Risco {proposta.risco}</span>
        <span>{proposta.exigeAprovacao ? "Exige aprovação humana" : "Sem aprovação humana"}</span>
        {proposta.nova && <span>Ação nova</span>}
        {proposta.promovida && <span>Promovida ao catálogo</span>}
        <span>Criada às <Instante valor={proposta.criadaEm} /></span>
      </div>
      {proposta.motivosDeRiscoAlto.length > 0 && (
        <ul className="proposal-reasons" aria-label="Motivos do risco alto">
          {proposta.motivosDeRiscoAlto.map((codigo) => <li key={codigo}>{MOTIVOS_DE_RISCO_ALTO[codigo]}</li>)}
        </ul>
      )}
      <p className="proposal-justification">Justificativa do agente: {aspas(proposta.justificativa)}</p>
      {proposta.decisoes.map((decisao) => (
        <div className="proposal-step" key={decisao.instante + decisao.tipo}>
          <Instante valor={decisao.instante} /> {decisao.tipo === "acao_aprovada" ? "Aprovada" : "Rejeitada"}{" "}
          {quemDecidiu(decisao.canal, decisao.usuario, decisao.motivo)}
        </div>
      ))}
      {proposta.execucoes.map((execucao) => (
        <Fragment key={execucao.id}>
          <div className="proposal-step">
            <Instante valor={execucao.aplicadaEm} /> Execução <code className="event-id">{execucao.id}</code> aplicada
          </div>
          {execucao.efeitos.map((efeito) => (
            <div className="proposal-step" key={efeito.instante + efeito.resultado}>
              <Instante valor={efeito.instante} /> Efeito verificado: {rotulo(RESULTADO_DO_EFEITO, efeito.resultado)}
            </div>
          ))}
          {execucao.desfeitaEm && (
            <div className="proposal-step">
              <Instante valor={execucao.desfeitaEm} /> Execução <code className="event-id">{execucao.id}</code> desfeita
            </div>
          )}
        </Fragment>
      ))}
    </li>
  );
}

export default function DetalheDoIncidente({ incidente: view }: Props) {
  const [mostrarRastroCompleto, setMostrarRastroCompleto] = useState(false);
  const dados = view.incidente;
  const rastro = view.eventos.filter(
    (evento): evento is EventoDeTool | EventoDeLLM => evento.tipo === "tool_chamada" || evento.tipo === "llm_chamada",
  );
  const historico = view.eventos.filter((evento) => EVENTOS_DO_HISTORICO.has(evento.tipo));
  const eventosVisiveis = mostrarRastroCompleto ? rastro : rastro.slice(0, RASTRO_RESUMIDO);
  const tokensTotal = view.tokensEntrada + view.tokensSaida;
  const propostasPorId = new Map(view.propostas.map((proposta) => [proposta.id, proposta]));
  const agentesDaRecomendacao = Array.from(new Set(view.recomendacoes.map((evento) => evento.dados.agente)));
  const marcacao = view.marcacao;

  return (
    <section className="detalhe">
      <div className="detail-heading">
        <div><div className="eyebrow">ANÁLISE DO ALERTA</div><h2>{view.id}</h2></div>
        <span className="replay-pill"><span className="status-dot" /> REPLAY</span>
      </div>
      <div className="replay-notice"><span>ⓘ</span><p><strong>Execução roteirizada.</strong> Valores ilustrativos do stub MCP: não representam tráfego, predição nem decisão reais de uma LLM.</p></div>
      {marcacao && (
        <div className="resolved-notice" role="status">
          <span>✓</span>
          <p>
            <strong>Marcado como já resolvido</strong> às <Instante valor={marcacao.instante} />,{" "}
            {quemDecidiu(marcacao.canal, marcacao.usuario, marcacao.motivo)}. Daqui em diante, o servidor recusa proposta e execução neste incidente.
          </p>
        </div>
      )}

      <div className="detail-grid">
        <article className="panel verdict-panel">
          <div className="panel-title"><span className="panel-icon model-icon">◈</span><div><h3>Veredito do modelo</h3><p>Random Forest · 39 features</p></div></div>
          <div className="verdict-summary">
            <div><span className="field-label">CATEGORIA DO INCIDENTE</span><strong className="attack-category">{dados.categoria}</strong></div>
            <div className="confidence-block"><strong>{Math.round(dados.confianca * 100)}<small>%</small></strong><span>confiança</span></div>
          </div>
          <div className="model-note">Saída do modelo: <strong>{dados.categoria_do_modelo}</strong>{dados.categoria !== dados.categoria_do_modelo && <span className="classification-note"> · refinada pela regra de origens</span>}</div>
          <div className="feature-title"><strong>Features em destaque</strong><span>vs. tráfego benigno</span></div>
          <div className="feature-list">
            {dados.features_principais.map((feature) => {
              const razao = Math.min(Math.abs(feature.valor) / (Math.abs(feature.referencia_benigno) || 1), 5);
              return <div className="feature-row" key={feature.nome}>
                <div className="feature-label"><strong>{feature.nome}</strong><span>{numero(feature.valor)}</span></div>
                <div className="feature-track"><span style={{ width: `${Math.max(4, (razao / 5) * 100)}%` }} /></div>
                <small>Benigno: {numero(feature.referencia_benigno)}</small>
              </div>;
            })}
          </div>
          <div className="incident-facts">
            <span><small>ORIGENS</small><strong>{dados.origens_distintas} dispositivos</strong></span>
            <span><small>VOLUME</small><strong>{inteiro(dados.janelas)} janelas</strong></span>
            <span><small>PERÍODO</small><strong><Instante valor={dados.inicio} /> a <Instante valor={dados.fim} /></strong></span>
          </div>
        </article>

        <article className="panel trace-panel" id="atividade">
          <div className="panel-title"><span className="panel-icon trace-icon">⌁</span><div><h3>Rastro dos agentes</h3><p>{rastro.length} eventos · {view.chamadasLLM} chamadas à IA</p></div></div>
          <div className="trace-summary"><span><strong>{inteiro(tokensTotal)}</strong><small>tokens totais</small></span><span><strong>{inteiro(view.tokensEntrada)}</strong><small>entrada</small></span><span><strong>{inteiro(view.tokensSaida)}</strong><small>saída</small></span></div>
          <ol className="timeline">
            {eventosVisiveis.map((evento) => (
              <li key={evento.id} className={evento.tipo === "llm_chamada" ? "timeline-llm" : "timeline-tool"}>
                <Instante valor={evento.instante} />
                <span className="timeline-node">{evento.tipo === "llm_chamada" ? "✳" : "↗"}</span>
                <div className="timeline-copy"><strong>{nomeDoAgente(evento.dados.agente)}</strong><span>{evento.tipo === "tool_chamada" ? `Tool · ${evento.dados.nome}` : `Modelo · ${evento.dados.modelo}`}</span></div>
                <small>{inteiro(Math.round(evento.dados.duracao_ms))} ms</small>
              </li>
            ))}
          </ol>
          {rastro.length > RASTRO_RESUMIDO && <button className="text-button" onClick={() => setMostrarRastroCompleto(!mostrarRastroCompleto)}>{mostrarRastroCompleto ? "Mostrar resumo" : `Ver todos os ${rastro.length} eventos`} <span>→</span></button>}
        </article>
      </div>

      <div className="lower-grid">
        <article className="panel recommendation-panel">
          <div className="panel-title">
            <span className="panel-icon recommendation-icon">✳</span>
            <div>
              <h3>Recomendação do agente</h3>
              <p>{agentesDaRecomendacao.length > 0 ? agentesDaRecomendacao.map((agente) => `Agente de ${rotulo(NOME_DO_AGENTE, agente).toLowerCase()}`).join(" · ") : "Nenhum agente"} · registro do replay</p>
            </div>
          </div>
          {view.recomendacoes.length === 0 ? <p className="empty-copy">Nenhuma recomendação neste registro.</p> : (
            <ol className="recommendation-list">
              {view.recomendacoes.map((evento) => (
                <li key={evento.id}>
                  <div className="recommendation-meta"><Instante valor={evento.instante} /> · Agente de {rotulo(NOME_DO_AGENTE, evento.dados.agente).toLowerCase()}</div>
                  <p className="recommendation-copy">{aspas(evento.dados.texto)}</p>
                  {evento.dados.propostas.length > 0 && (
                    <ul className="recommendation-proposals" aria-label="Propostas ligadas à recomendação">
                      {evento.dados.propostas.map((id) => {
                        const proposta = propostasPorId.get(id);
                        return (
                          <li key={id}>
                            <code className="event-id">{id}</code>
                            {proposta
                              ? ` ${proposta.acao} em ${alvoNaTela(proposta.alvo, proposta.alvoComRotulo)} · ${rotulo(ESTADO_DA_PROPOSTA, proposta.estado)}`
                              : " proposta não encontrada neste incidente"}
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </li>
              ))}
            </ol>
          )}
        </article>

        <article className="panel proposals-panel">
          <div className="panel-title"><span className="panel-icon actions-icon">◇</span><div><h3>Propostas de ação</h3><p>Estado de cada proposta depois do último evento</p></div></div>
          {view.propostas.length === 0 ? <p className="empty-copy">Nenhuma proposta neste registro.</p> : (
            <ul className="proposal-list">
              {view.propostas.map((proposta) => <CartaoDaProposta key={proposta.id} proposta={proposta} />)}
            </ul>
          )}
        </article>
      </div>

      <article className="panel actions-panel">
        <div className="panel-title"><span className="panel-icon actions-icon">✓</span><div><h3>Decisões e ações</h3><p>Histórico registrado no log, em ordem</p></div></div>
        <ul className="action-list">
          {historico.map((evento) => {
            const linha = linhaDoHistorico(evento);
            if (!linha) {
              return null;
            }
            // O CSS corta a descrição com reticências; o texto inteiro fica no title.
            return (
              <li key={evento.id}>
                <Instante valor={evento.instante} />
                <span className={`action-status status-${evento.tipo}`}><span />{rotulo(ROTULO_DO_EVENTO, evento.tipo)}</span>
                <code className="event-id">{linha.id}</code>
                <span className="action-description" title={linha.descricao}>{linha.descricao}</span>
              </li>
            );
          })}
        </ul>
        <div className="replay-lock"><span>▣</span> Controles desativados durante o replay</div>
      </article>
    </section>
  );
}
