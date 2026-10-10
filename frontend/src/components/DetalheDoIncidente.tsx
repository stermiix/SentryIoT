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
  catalogo_ampliado: "Promovida ao catálogo",
  recusa: "Recusada pelo servidor",
};

// Nome de cada agente como aparece na tela. No log vai sem acento (`AGENTES` em tipos.py).
const NOME_DO_AGENTE: Record<string, string> = {
  triagem: "Triagem",
  decisao: "Decisão",
  execucao: "Execução",
};

const RESULTADO_DO_EFEITO: Record<string, string> = {
  cessou: "o incidente cessou",
  diminuiu: "o incidente diminuiu",
  persiste: "o incidente persiste",
};

// O que cada tipo traz em `dados` é diferente (ver a tabela do log em codigo/mcp/README.md):
// proposta e execução têm ação e alvo; decisão e promoção apontam para a proposta; o efeito
// aponta para a execução; a recusa traz a tool.
function descricaoDaAcao(evento: Evento): string {
  const dados = evento.dados;
  switch (evento.tipo) {
    case "acao_aprovada":
    case "acao_rejeitada":
      return dados.motivo ? `${dados.proposta} · ${dados.motivo}` : dados.proposta;
    case "efeito_verificado":
      return `${dados.execucao} · ${RESULTADO_DO_EFEITO[dados.resultado] ?? dados.resultado}`;
    case "catalogo_ampliado":
      return `${dados.acao?.nome ?? dados.proposta} (de ${dados.proposta})`;
    case "recusa":
      return `${dados.tool} · ${dados.mensagem}`;
    default:
      return dados.alvo ? `${dados.acao} em ${dados.alvo}` : dados.acao;
  }
}

// Valores de feature como o IAT (2,8e-5) virariam "0" com o arredondamento padrão de três casas.
function numero(valor: number): string {
  const opcoes = Math.abs(valor) < 1 && valor !== 0 ? { maximumSignificantDigits: 3 } : undefined;
  return valor.toLocaleString("pt-BR", opcoes);
}

export default function DetalheDoIncidente({ incidente }: Props) {
  const [mostrarRastroCompleto, setMostrarRastroCompleto] = useState(false);
  const dados = incidente.incidente;
  const rastro = incidente.eventos.filter(
    (evento) => evento.tipo === "tool_chamada" || evento.tipo === "llm_chamada",
  );
  const acoes = incidente.eventos.filter((evento) => ROTULO_DO_EVENTO[evento.tipo] !== undefined);
  const eventosVisiveis = mostrarRastroCompleto ? rastro : rastro.slice(0, 7);
  const tokensTotal = incidente.tokensEntrada + incidente.tokensSaida;

  return (
    <section className="detalhe">
      <div className="detail-heading">
        <div><div className="eyebrow">ANÁLISE DO ALERTA</div><h2>{incidente.id}</h2></div>
        <span className="replay-pill"><span className="status-dot" /> REPLAY</span>
      </div>
      <div className="replay-notice"><span>ⓘ</span><p><strong>Execução roteirizada.</strong> Valores ilustrativos do stub MCP: não representam tráfego, predição nem decisão reais de uma LLM.</p></div>

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
                    <div className="feature-label"><strong>{feature.nome}</strong><span>{numero(feature.valor)}</span></div>
                    <div className="feature-track"><span style={{ width: `${Math.max(4, (ratio / 5) * 100)}%` }} /></div>
                    <small>Benigno: {numero(feature.referencia_benigno)}</small>
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
                {/* `agente` é nulo na tool_chamada quando o stub sobe com `--agente todos`. */}
                <div className="timeline-copy"><strong>{NOME_DO_AGENTE[evento.dados.agente] ?? evento.dados.agente ?? "Agente não identificado"}</strong><span>{evento.tipo === "tool_chamada" ? `Tool · ${evento.dados.nome}` : `Modelo · ${evento.dados.modelo}`}</span></div>
                <small>{Math.round(evento.dados.duracao_ms).toLocaleString("pt-BR")} ms</small>
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
            {acoes.map((evento) => {
              const descricao = descricaoDaAcao(evento);
              // O CSS corta a descrição com reticências; o texto inteiro fica no title.
              return <li key={evento.id}><span className={`action-status status-${evento.tipo}`}><span />{ROTULO_DO_EVENTO[evento.tipo]}</span><span className="action-description" title={descricao}>{descricao}</span></li>;
            })}
          </ul>
          <div className="replay-lock"><span>▣</span> Controles desativados durante o replay</div>
        </article>
      </div>
    </section>
  );
}
