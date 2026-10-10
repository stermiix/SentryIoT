import { useState } from "react";
import type { Evento, IncidenteView } from "../types";

interface Props {
  incidente: IncidenteView;
}

// Rótulo e cor de cada tipo de evento de decisão, para a lista de ações.
const ROTULO_DO_EVENTO: Record<string, string> = {
  acao_proposta: "Proposta criada",
  acao_aprovada: "Aprovada",
  acao_rejeitada: "Rejeitada",
  acao_executada: "Executada",
  acao_desfeita: "Desfeita",
  efeito_verificado: "Efeito verificado",
  recusa: "Recusada pelo servidor",
};

function descricaoDaAcao(evento: Evento): string {
  const dados = evento.dados;
  const alvo = dados.alvo ? ` em ${dados.alvo}` : "";
  return `${dados.acao ?? dados.proposta ?? dados.tool ?? ""}${alvo}`;
}

export default function DetalheDoIncidente({ incidente }: Props) {
  const [mostrarRastroCompleto, setMostrarRastroCompleto] = useState(false);
  const dados = incidente.incidente;
  const rastro = incidente.eventos.filter(
    (evento) => evento.tipo === "tool_chamada" || evento.tipo === "llm_chamada",
  );
  const acoes = incidente.eventos.filter((evento) => evento.tipo in ROTULO_DO_EVENTO);
  const eventosVisiveis = mostrarRastroCompleto ? rastro : rastro.slice(0, 7);
  const tokensTotal = incidente.tokensEntrada + incidente.tokensSaida;

  return (
    <section className="detalhe">
      <div className="detail-heading">
        <div><div className="eyebrow">ANÁLISE DO ALERTA</div><h2>{incidente.id}</h2></div>
        <span className="replay-pill"><span className="status-dot" /> REPLAY</span>
      </div>
      <div className="replay-notice"><span>ⓘ</span><p><strong>Execução roteirizada.</strong> Valores ilustrativos do stub MCP — não representam tráfego, predição ou decisão de uma LLM reais.</p></div>

      <div className="detail-grid">
        <article className="panel verdict-panel">
          <div className="panel-title"><span className="panel-icon model-icon">◈</span><div><h3>Veredito do modelo</h3><p>Random Forest · 39 features</p></div></div>
          {dados ? (
            <>
              <div className="verdict-summary">
                <div><span className="field-label">CATEGORIA DO INCIDENTE</span><strong className="attack-category">{dados.categoria}</strong></div>
                <div className="confidence-block"><strong>{Math.round(dados.confianca * 100)}<small>%</small></strong><span>confiança</span></div>
              </div>
              <div className="model-note">Saída do modelo: <strong>{dados.categoria_do_modelo}</strong>{dados.categoria !== dados.categoria_do_modelo && <span className="classification-note"> · refinada pela regra de origens</span>}</div>
              <div className="feature-title"><strong>Features em destaque</strong><span>vs. tráfego benigno</span></div>
              <div className="feature-list">
                {dados.features_principais.map((feature) => {
                  const ratio = Math.min(Math.abs(feature.valor) / (Math.abs(feature.referencia_benigno) || 1), 5);
                  return <div className="feature-row" key={feature.nome}>
                    <div className="feature-label"><strong>{feature.nome}</strong><span>{feature.valor.toLocaleString("pt-BR")}</span></div>
                    <div className="feature-track"><span style={{ width: `${Math.max(4, (ratio / 5) * 100)}%` }} /></div>
                    <small>Benigno: {feature.referencia_benigno.toLocaleString("pt-BR")}</small>
                  </div>;
                })}
              </div>
              <div className="incident-facts"><span><small>ORIGENS</small><strong>{dados.origens_distintas} dispositivos</strong></span><span><small>VOLUME</small><strong>{dados.janelas.toLocaleString("pt-BR")} janelas</strong></span></div>
            </>
          ) : <p>Sem dados do incidente neste trecho do log.</p>}
        </article>

        <article className="panel trace-panel" id="atividade">
          <div className="panel-title"><span className="panel-icon trace-icon">⌁</span><div><h3>Rastro dos agentes</h3><p>{rastro.length} eventos · {incidente.chamadasLLM} chamadas à IA</p></div></div>
          <div className="trace-summary"><span><strong>{tokensTotal.toLocaleString("pt-BR")}</strong><small>tokens totais</small></span><span><strong>{incidente.tokensEntrada.toLocaleString("pt-BR")}</strong><small>entrada</small></span><span><strong>{incidente.tokensSaida.toLocaleString("pt-BR")}</strong><small>saída</small></span></div>
          <ol className="timeline">
            {eventosVisiveis.map((evento) => (
              <li key={evento.id} className={evento.tipo === "llm_chamada" ? "timeline-llm" : "timeline-tool"}>
                <span className="timeline-node">{evento.tipo === "llm_chamada" ? "✳" : "↗"}</span>
                <div className="timeline-copy"><strong>{evento.dados.agente}</strong><span>{evento.tipo === "tool_chamada" ? `Tool · ${evento.dados.nome}` : `Modelo · ${evento.dados.modelo}`}</span></div>
                <small>{evento.dados.duracao_ms} ms</small>
              </li>
            ))}
          </ol>
          {rastro.length > 7 && <button className="text-button" onClick={() => setMostrarRastroCompleto(!mostrarRastroCompleto)}>{mostrarRastroCompleto ? "Mostrar resumo" : `Ver todos os ${rastro.length} eventos`} <span>→</span></button>}
        </article>
      </div>

      <div className="lower-grid">
        <article className="panel recommendation-panel">
          <div className="panel-title"><span className="panel-icon recommendation-icon">✳</span><div><h3>Recomendação do agente</h3><p>Agente de decisão · registro do replay</p></div></div>
          {incidente.recomendacoes.length === 0 ? <p className="empty-copy">Nenhuma recomendação neste registro.</p> : incidente.recomendacoes.map((evento) => <p key={evento.id} className="recommendation-copy">“{evento.dados.texto}”</p>)}
        </article>

        <article className="panel actions-panel">
          <div className="panel-title"><span className="panel-icon actions-icon">✓</span><div><h3>Decisões e ações</h3><p>Histórico registrado no log</p></div></div>
          <ul className="action-list">
            {acoes.map((evento) => (
              <li key={evento.id}><span className={`action-status status-${evento.tipo}`}><span />{ROTULO_DO_EVENTO[evento.tipo]}</span><span className="action-description">{descricaoDaAcao(evento)}</span></li>
            ))}
          </ul>
          <div className="replay-lock"><span>▣</span> Controles desativados durante o replay</div>
        </article>
      </div>
    </section>
  );
}
