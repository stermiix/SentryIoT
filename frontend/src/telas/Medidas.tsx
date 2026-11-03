import type { ReactNode } from "react";
import { Alert, Button, Icon, Select, VERDICT, fmtConfidence, fmtDuration, fmtInt, fmtPct } from "../design-system";
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

/** Uma medida lida: sim, não ou nem um nem outro (nulo), com o texto longo e o curto (a barra e a tabela). */
export interface Leitura {
  ok: boolean | null;
  longo: string;
  curto: string;
}

export interface LeiturasDaExecucao {
  /** A rodada terminou em erro: fica fora das taxas, e nenhuma medida dela é acerto ou erro dos agentes. */
  comErro: boolean;
  triagem: Leitura;
  acao: Leitura;
  atacante: Leitura;
}

/**
 * O que cada medida da rodada quer dizer, para a tela não chamar de erro do agente o que não é: a rodada
 * que terminou em erro fica fora das taxas, e o incidente verdadeiro com confiança abaixo da mínima só
 * recebe recomendação, por regra do servidor. Os números das taxas continuam os do experimento.
 */
/**
 * Incidente verdadeiro, confiança abaixo da mínima e nenhuma proposta: o servidor recusa `propor_acao`
 * (`incidente_duvidoso`), e os agentes só recomendam. Na taxa, conta como não aceitável, como no experimento.
 */
export function soRecomenda(execucao: ExecucaoDaRodada, minima: number): boolean {
  return execucao.desfecho !== "erro" && execucao.verdadeiro && execucao.confianca < minima && execucao.n_propostas === 0;
}

export function lerExecucao(execucao: ExecucaoDaRodada, minima: number): LeiturasDaExecucao {
  if (execucao.desfecho === "erro") {
    const fora = { ok: null, longo: "rodada com erro, fora das taxas", curto: "fora das taxas" };
    return { comErro: true, triagem: { ...fora, curto: "rodada com erro" }, acao: fora, atacante: fora };
  }
  const { verdadeiro } = execucao;
  const rotulo = execucao.triagem_rotulo ? VERDICT[execucao.triagem_rotulo] : "sem rótulo";
  const triagem = {
    ok: execucao.triagem_correta,
    longo: `${rotulo} · ${execucao.triagem_correta ? "certa" : "errada"}`,
    curto: rotulo,
  };
  const acaoPrimeira = execucao.acao_primeira ?? "nenhuma proposta";
  let acao: Leitura;
  if (soRecomenda(execucao, minima)) {
    const regra = `confiança abaixo de ${fmtConfidence(minima)} (regra do servidor)`;
    acao = { ok: null, longo: `só recomendação: ${regra}`, curto: "só recomendação" };
  } else if (verdadeiro) {
    acao = {
      ok: execucao.primeira_aceitavel,
      longo: `${acaoPrimeira} · ${execucao.primeira_aceitavel ? "aceitável pelo gabarito" : "fora do gabarito"}`,
      curto: execucao.acao_primeira ?? "nenhuma",
    };
  } else {
    acao = { ok: null, longo: `${acaoPrimeira} · num incidente falso, nenhuma ação conta como certa`, curto: execucao.acao_primeira ?? "nenhuma" };
  }
  let atacante: Leitura;
  if (!verdadeiro) {
    atacante = {
      ok: null,
      longo: `${execucao.atacante_apontado ? "apontado" : "nenhum atacante apontado"} · sem atacante certo num incidente falso`,
      curto: "não se aplica",
    };
  } else if (!execucao.atacante_apontado) {
    atacante = { ok: false, longo: `nenhum atacante apontado · a regra fixa ${execucao.origem_da_regra_certa ? "acerta" : "erra"}`, curto: "nenhum apontado" };
  } else {
    atacante = {
      ok: execucao.atacante_certo,
      longo: `${execucao.atacante_certo ? "certo" : "errado"} · a regra fixa ${execucao.origem_da_regra_certa ? "acerta" : "erra"}`,
      curto: execucao.atacante_certo ? "certo" : "errado",
    };
  }
  return { comErro: false, triagem, acao, atacante };
}

/** As medidas da rodada numa execução, como o experimento as grava, em itens curtos. */
export function itensDaMedida(execucao: ExecucaoDaRodada, minima: number): { rotulo: string; valor: ReactNode }[] {
  const { verdadeiro } = execucao;
  const leitura = lerExecucao(execucao, minima);
  return [
    {
      rotulo: "Verdade de campo",
      valor: verdadeiro ? `ataque de ${execucao.categoria_do_pcap}` : `incidente falso (pcap ${execucao.categoria_do_pcap})`,
    },
    { rotulo: "Confiança", valor: fmtConfidence(execucao.confianca) },
    { rotulo: "Triagem", valor: <Marca ok={leitura.triagem.ok}>{leitura.triagem.longo}</Marca> },
    { rotulo: "Primeira ação", valor: <Marca ok={leitura.acao.ok}>{leitura.acao.longo}</Marca> },
    { rotulo: "Atacante apontado", valor: <Marca ok={leitura.atacante.ok}>{leitura.atacante.longo}</Marca> },
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
export function MedidasDaExecucao({ execucao, minima }: { execucao: ExecucaoDaRodada; minima: number }) {
  return (
    <div className="sx-stack sx-stack--sm">
      <dl className="sx-kv body-sm app-medidas">
        {itensDaMedida(execucao, minima).map((item) => (
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
  const leitura = lerExecucao(execucao, indice.confianca_minima_para_propor);
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
            onChange={(valor) => escolher?.(trocarNoSeletor(rodada, campo, valor))}
          />
        ))}
      </div>
      <p className="body-sm app-fonte__medidas">
        {leitura.comErro ? (
          <Marca ok={null}>rodada com erro, fora das taxas</Marca>
        ) : (
          <>
            <Marca ok={execucao.triagem_correta}>triagem {execucao.triagem_correta ? "certa" : "errada"}</Marca>
            {execucao.verdadeiro ? (
              <>
                <Marca ok={leitura.acao.ok}>
                  {leitura.acao.ok === null ? leitura.acao.longo : `primeira ação ${execucao.primeira_aceitavel ? "aceitável" : "fora do gabarito"}`}
                </Marca>
                <Marca ok={leitura.atacante.ok}>
                  {execucao.atacante_apontado ? `atacante ${execucao.atacante_certo ? "certo" : "errado"}` : "nenhum atacante apontado"}
                </Marca>
              </>
            ) : (
              <Marca ok={null}>incidente falso</Marca>
            )}
          </>
        )}
        <span className="sx-muted">
          {rotuloDoDesfecho(execucao.desfecho)} · {fmtInt(execucao.tokens_entrada + execucao.tokens_saida)} tokens · {fmtDuration(execucao.agentes_s)} dos agentes
        </span>
      </p>
      <p className="body-sm sx-muted app-nota">
        Nesta execução, os agentes trataram só o <span className="data-sm">{execucao.incidente}</span>; os outros incidentes do mesmo pcap aparecem como o classificador os abriu.
        {carregando && " Carregando o log da execução…"}
      </p>
    </section>
  );
}
