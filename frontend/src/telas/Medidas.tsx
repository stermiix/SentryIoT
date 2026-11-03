import type { ReactNode } from "react";
import { Alert, Button, Icon, Select, VERDICT, fmtDuration, fmtInt, fmtPct } from "../design-system";
import {
  opcoesDoSeletor,
  rotuloDoDesfecho,
  trocarNoSeletor,
  type CampoDoSeletor,
  type ContextoDaRodada,
  type ExecucaoDaRodada,
  type Taxa,
} from "../rodada";
import type { ResultadoDaSimulacao } from "../simulacao";

// O que a rodada mediu em cada execução, e a barra que diz de onde vem o log das telas: a rodada final
// (com o seletor de execução) ou uma simulação.

/** Sim ou não, com ícone e palavra: a cor nunca é a única pista. */
export function Marca({ ok, children }: { ok: boolean | null; children: ReactNode }) {
  const icone = ok === null ? "minus" : ok ? "circle-check" : "circle-x";
  return (
    <span className={ok === null ? "app-marca" : ok ? "app-marca is-sim" : "app-marca is-nao"}>
      <Icon name={icone} size={14} />
      {children}
    </span>
  );
}

/** `3 de 4 (75%)`. */
export function taxa({ acertos, de }: Taxa): string {
  return de > 0 ? `${fmtInt(acertos)} de ${fmtInt(de)} (${fmtPct(acertos / de)})` : "sem caso";
}

/** As medidas da rodada numa execução, como o experimento as grava, em itens curtos. */
export function itensDaMedida(execucao: ExecucaoDaRodada): { rotulo: string; valor: ReactNode }[] {
  const { verdadeiro } = execucao;
  const rotulo = execucao.triagem_rotulo ? VERDICT[execucao.triagem_rotulo] : "sem rótulo";
  return [
    {
      rotulo: "Verdade de campo",
      valor: verdadeiro ? `ataque de ${execucao.categoria_do_pcap}` : `incidente falso (pcap ${execucao.categoria_do_pcap})`,
    },
    { rotulo: "Triagem", valor: <Marca ok={execucao.triagem_correta}>{rotulo} · {execucao.triagem_correta ? "certa" : "errada"}</Marca> },
    {
      rotulo: "Primeira ação",
      valor: verdadeiro ? (
        <Marca ok={execucao.primeira_aceitavel}>
          {execucao.acao_primeira ?? "nenhuma proposta"} · {execucao.primeira_aceitavel ? "aceitável pelo gabarito" : "fora do gabarito"}
        </Marca>
      ) : (
        <Marca ok={null}>{execucao.acao_primeira ?? "nenhuma proposta"} · num incidente falso, nenhuma ação conta como certa</Marca>
      ),
    },
    {
      rotulo: "Atacante apontado",
      valor: verdadeiro ? (
        <Marca ok={execucao.atacante_certo}>
          {execucao.atacante_apontado ? (execucao.atacante_certo ? "certo" : "errado") : "não apontado"} · a regra fixa {execucao.origem_da_regra_certa ? "acerta" : "erra"}
        </Marca>
      ) : (
        <Marca ok={null}>{execucao.atacante_apontado ? "apontado" : "não apontado"} · sem atacante certo num incidente falso</Marca>
      ),
    },
    { rotulo: "Desfecho", valor: rotuloDoDesfecho(execucao.desfecho) },
    {
      rotulo: "Propostas",
      valor: `${fmtInt(execucao.n_propostas)} · ${fmtInt(execucao.n_aprovadas)} ${execucao.n_aprovadas === 1 ? "aprovada" : "aprovadas"} e ${fmtInt(execucao.n_rejeitadas)} ${
        execucao.n_rejeitadas === 1 ? "rejeitada" : "rejeitadas"
      } pelo aprovador automático · ${fmtInt(execucao.n_baixo_risco)} de risco baixo`,
    },
    {
      rotulo: "Custo e tempo",
      valor: `${fmtInt(execucao.tokens_entrada + execucao.tokens_saida)} tokens em ${fmtInt(execucao.chamadas)} chamadas · ${fmtDuration(execucao.agentes_s)} dos agentes · detecção em ${fmtDuration(execucao.deteccao_s)}`,
    },
  ];
}

/** As medidas da execução, para o painel do incidente e a aba da conversa. */
export function MedidasDaExecucao({ execucao }: { execucao: ExecucaoDaRodada }) {
  return (
    <div className="sx-stack sx-stack--sm">
      <dl className="sx-kv body-sm app-medidas">
        {itensDaMedida(execucao).map((item) => (
          <div key={item.rotulo} className="app-medidas__item">
            <dt>{item.rotulo}</dt>
            <dd>{item.valor}</dd>
          </div>
        ))}
      </dl>
      {execucao.erro && <p className="body-sm sx-muted app-nota">A rodada terminou em erro: {execucao.erro}</p>}
      {execucao.avisos.length > 0 && (
        <ul className="app-avisos body-sm sx-muted" aria-label="Avisos do orquestrador">
          {execucao.avisos.map((aviso, indice) => (
            <li key={indice}>{aviso}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

const ROTULO_DO_CAMPO: Record<CampoDoSeletor, string> = {
  grupo: "Grupo",
  pcap: "Captura (pcap)",
  incidente: "Incidente",
  repeticao: "Repetição",
};

export interface PropsDaBarra {
  /** A execução da rodada final que as telas mostram. */
  rodada: ContextoDaRodada | null;
  /** O build não trouxe os dados da rodada final. */
  semDados?: boolean;
  /** A simulação cujo log está nas telas, quando há. */
  simulacao: ResultadoDaSimulacao | null;
  /** Os agentes da simulação ainda rodam: voltar à rodada final largaria as decisões pendentes. */
  simulacaoAtiva?: boolean;
  /** A execução está sendo carregada. */
  carregando?: boolean;
  escolher?: (id: string) => void;
  voltar?: () => void;
  abrirRodada?: () => void;
  /** O nome da fonte para onde a simulação volta: a rodada final ou o log de VITE_LOG_DE_EVENTOS. */
  voltarPara?: string;
}

/** A barra no alto das telas que dependem do log: de onde vem o log e, na rodada final, qual execução. */
export function BarraDaFonte({ rodada, semDados = false, simulacao, simulacaoAtiva = false, carregando = false, escolher, voltar, abrirRodada, voltarPara = "à rodada final" }: PropsDaBarra) {
  if (simulacao) {
    return (
      <section className="app-fonte" aria-label="De onde vem o log">
        <div className="app-fonte__linha">
          <span className="app-fonte__titulo">
            <Icon name="upload" size={16} />
            <span className="sx-eyebrow eyebrow">Simulação</span>
            <span className="data-sm">{simulacao.arquivo}</span>
          </span>
          <span className="body-sm sx-muted app-fonte__texto">As telas mostram o log desta simulação.</span>
          <Button
            size="sm"
            variant="secondary"
            icon="history"
            disabled={simulacaoAtiva}
            title={simulacaoAtiva ? "Os agentes da simulação ainda rodam: pare-os na tela Simulação antes de voltar." : undefined}
            onClick={voltar}
          >
            Voltar {voltarPara}
          </Button>
        </div>
      </section>
    );
  }
  if (semDados) {
    return (
      <Alert title="Os dados da rodada final não estão neste build.">
        Gere-os com <span className="data-sm">python -m codigo.agente.vitrine</span> e rode <span className="data-sm">npm run build</span> de novo. A simulação com um pcap continua disponível.
      </Alert>
    );
  }
  if (!rodada) {
    return null;
  }
  const opcoes = opcoesDoSeletor(rodada);
  const { execucao, indice } = rodada;
  const campos: CampoDoSeletor[] = ["grupo", "pcap", "incidente", "repeticao"];
  return (
    <section className="app-fonte" aria-label="Execução da rodada final">
      <div className="app-fonte__linha">
        <span className="app-fonte__titulo">
          <Icon name="clipboard-check" size={16} />
          <span className="sx-eyebrow eyebrow">Rodada final · execução gravada</span>
        </span>
        <span className="body-sm sx-muted app-fonte__texto">
          Modelo local <span className="data-sm">{indice.modelos.join(", ") || "não informado"}</span> nos três agentes · aprovação automática por regra fixa · efeito simulado
        </span>
        {abrirRodada && (
          <Button size="sm" variant="ghost" icon="list-checks" onClick={abrirRodada}>
            Todas as execuções
          </Button>
        )}
      </div>
      <div className="app-fonte__seletor">
        {campos.map((campo) => (
          <Select
            key={campo}
            className={`app-fonte__campo app-fonte__campo--${campo}`}
            label={ROTULO_DO_CAMPO[campo]}
            options={opcoes[campo]}
            value={opcoes.valor[campo]}
            disabled={carregando}
            onChange={(valor) => escolher?.(trocarNoSeletor(rodada, campo, valor))}
          />
        ))}
      </div>
      <p className="body-sm app-fonte__medidas">
        <Marca ok={execucao.triagem_correta}>triagem {execucao.triagem_correta ? "certa" : "errada"}</Marca>
        {execucao.verdadeiro ? (
          <>
            <Marca ok={execucao.primeira_aceitavel}>primeira ação {execucao.primeira_aceitavel ? "aceitável" : "fora do gabarito"}</Marca>
            <Marca ok={execucao.atacante_certo}>atacante {execucao.atacante_certo ? "certo" : "errado"}</Marca>
          </>
        ) : (
          <Marca ok={null}>incidente falso</Marca>
        )}
        <span className="sx-muted">
          {rotuloDoDesfecho(execucao.desfecho)} · {fmtInt(execucao.tokens_entrada + execucao.tokens_saida)} tokens · {fmtDuration(execucao.agentes_s)} dos agentes
        </span>
      </p>
      <p className="body-sm sx-muted app-nota">
        Nesta execução, os agentes trataram só o <span className="data-sm">{execucao.incidente}</span>; os outros incidentes do mesmo pcap aparecem como o classificador os abriu.
        {carregando && " Carregando a execução…"}
      </p>
    </section>
  );
}
