import {
  AGENT,
  CATEGORY,
  CategoryBadge,
  EmptyState,
  PageHeader,
  Panel,
  Skeleton,
  VERDICT,
  cx,
  fmtConfidence,
  fmtDuration,
  fmtInt,
  fmtNum,
  type AnyCategory,
} from "../design-system";
import { rotuloDoDesfecho, type ExecucaoDaRodada, type GrupoDaRodada, type IndiceDaRodada } from "../rodada";
import { Marca, taxa } from "./Medidas";

// A tela "Rodada final": os grupos da rodada que vai com a interface, o resumo de cada um, calculado das
// medidas, e a tabela das execuções, de onde se abre qualquer uma nas outras telas.

function Categoria({ nome }: { nome: string }) {
  return nome in CATEGORY ? <CategoryBadge category={nome as AnyCategory} size="sm" /> : <span className="data-sm">{nome}</span>;
}

function Numero({ rotulo, valor, contexto }: { rotulo: string; valor: string; contexto?: string }) {
  return (
    <div className="app-numero">
      <span className="sx-eyebrow eyebrow">{rotulo}</span>
      <span className="app-numero__valor title-2">{valor}</span>
      {contexto && <span className="body-sm sx-muted">{contexto}</span>}
    </div>
  );
}

function Resumo({ grupo, minima }: { grupo: GrupoDaRodada; minima: number }) {
  const { resumo } = grupo;
  const segundos = (valor: number | null) => (valor === null ? "–" : fmtDuration(valor));
  return (
    <div className="app-numeros">
      <Numero rotulo="Triagem certa" valor={taxa(resumo.triagem_correta)} contexto="coerente no verdadeiro; duvidoso ou ruído no falso" />
      <Numero rotulo="Primeira ação aceitável" valor={taxa(resumo.acao_aceitavel)} contexto="pelo gabarito, nos incidentes verdadeiros" />
      <Numero rotulo="Atacante certo" valor={taxa(resumo.atacante_certo)} contexto={`a regra fixa acerta ${taxa(resumo.regra_fixa_certa)}`} />
      <Numero
        rotulo={`Abaixo de ${fmtNum(minima, 1)}`}
        valor={fmtInt(resumo.abaixo_da_confianca_minima)}
        contexto="execuções em que os agentes só podem recomendar"
      />
      <Numero rotulo="Tokens por execução" valor={resumo.mediana_tokens === null ? "–" : fmtInt(resumo.mediana_tokens)} contexto="mediana, entrada e saída" />
      <Numero rotulo="Tempo dos agentes" valor={segundos(resumo.mediana_agentes_s)} contexto={`mediana; detecção em ${segundos(resumo.mediana_deteccao_s)}`} />
    </div>
  );
}

function Linha({ execucao, atual, abrir }: { execucao: ExecucaoDaRodada; atual: boolean; abrir: (execucao: ExecucaoDaRodada) => void }) {
  return (
    <tr className={cx(atual && "app-linha-atual")} aria-current={atual ? "true" : undefined}>
      <td>
        <span className="app-empilhado">
          <button
            type="button"
            className="sx-rowlink data-sm"
            title={atual ? "Esta execução está aberta nas outras telas" : "Abrir esta execução nas outras telas, na conversa dos agentes"}
            onClick={() => abrir(execucao)}
          >
            {execucao.pcap}
          </button>
          <span className="data-sm sx-muted">
            {execucao.incidente} · repetição {execucao.repeticao}
            {atual && " · aberta"}
          </span>
        </span>
      </td>
      <td>
        <span className="app-empilhado">
          <Categoria nome={execucao.categoria} />
          <span className="body-sm sx-muted">
            {execucao.verdadeiro ? "verdadeiro" : `falso · pcap ${execucao.categoria_do_pcap}`} · confiança {fmtConfidence(execucao.confianca)}
          </span>
        </span>
      </td>
      <td>
        <Marca ok={execucao.triagem_correta}>{execucao.triagem_rotulo ? VERDICT[execucao.triagem_rotulo] : "sem rótulo"}</Marca>
      </td>
      <td>
        {execucao.verdadeiro ? (
          <Marca ok={execucao.primeira_aceitavel}>{execucao.acao_primeira ?? "nenhuma"}</Marca>
        ) : (
          <Marca ok={null}>{execucao.acao_primeira ?? "nenhuma"}</Marca>
        )}
      </td>
      <td>
        {execucao.verdadeiro ? (
          <Marca ok={execucao.atacante_certo}>{execucao.atacante_certo ? "certo" : "errado"}</Marca>
        ) : (
          <span className="body-sm sx-muted">não se aplica</span>
        )}
      </td>
      <td className="body-sm">{rotuloDoDesfecho(execucao.desfecho)}</td>
      <td className="is-num">
        <span className="app-empilhado">
          <span className="data">{fmtInt(execucao.tokens_entrada + execucao.tokens_saida)}</span>
          <span className="data-sm sx-muted">{fmtDuration(execucao.agentes_s)}</span>
        </span>
      </td>
    </tr>
  );
}

function Grupo({ grupo, minima, atual, abrir }: { grupo: GrupoDaRodada; minima: number; atual: string | null; abrir: (execucao: ExecucaoDaRodada) => void }) {
  const { resumo } = grupo;
  const contagem = [
    `${fmtInt(resumo.execucoes)} ${resumo.execucoes === 1 ? "execução" : "execuções"}`,
    `${fmtInt(resumo.pcaps)} ${resumo.pcaps === 1 ? "pcap" : "pcaps"}`,
    `${fmtInt(resumo.incidentes)} ${resumo.incidentes === 1 ? "incidente" : "incidentes"}`,
    `${fmtInt(resumo.repeticoes)} ${resumo.repeticoes === 1 ? "repetição" : "repetições"}`,
    ...(resumo.com_erro > 0 ? [`${fmtInt(resumo.com_erro)} com erro, fora das taxas`] : []),
  ].join(" · ");
  return (
    <Panel eyebrow={contagem} title={grupo.titulo} flush>
      <div className="app-grupo">
        <p className="body sx-muted app-nota">{grupo.descricao} O nome do pcap abre a execução nas outras telas.</p>
        <Resumo grupo={grupo} minima={minima} />
        {resumo.por_agente.length > 0 && (
          <p className="body-sm sx-muted app-nota">
            Por agente, mediana por execução:{" "}
            {resumo.por_agente
              .map((linha) => `${AGENT[linha.agente].label} ${fmtInt(linha.mediana_tokens ?? 0)} tokens em ${fmtDuration(linha.mediana_llm_s ?? 0)}`)
              .join(" · ")}
            .
          </p>
        )}
      </div>
      <div className="sx-tablewrap">
        <table className="sx-table app-tabela-da-rodada">
          <thead>
            <tr>
              <th scope="col">Captura e incidente</th>
              <th scope="col">Categoria detectada</th>
              <th scope="col">Triagem</th>
              <th scope="col">Primeira ação</th>
              <th scope="col">Atacante</th>
              <th scope="col">Desfecho</th>
              <th scope="col" className="is-num">Tokens e tempo</th>
            </tr>
          </thead>
          <tbody>
            {grupo.execucoes.map((execucao) => (
              <Linha key={execucao.id} execucao={execucao} atual={execucao.id === atual} abrir={abrir} />
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

export interface PropsDaRodada {
  indice: IndiceDaRodada | null;
  /** O índice ainda está sendo lido. */
  carregando?: boolean;
  /** A execução aberta nas outras telas. */
  atual: string | null;
  /** Abre a execução nas outras telas e vai para a conversa do incidente dela. */
  abrir: (execucao: ExecucaoDaRodada) => void;
}

/** Os grupos da rodada final, com o resumo e as execuções. */
export function TelaRodada({ indice, carregando = false, atual, abrir }: PropsDaRodada) {
  const cabecalho = (
    <PageHeader
      eyebrow="Operação"
      title="Rodada final"
      meta={
        <span className="body-sm sx-muted">
          As execuções gravadas dos experimentos dos agentes, que vão junto com a interface. Os três agentes rodam no modelo local
          {indice ? (
            <>
              {" "}
              <span className="data-sm">{indice.modelos.join(", ")}</span>
            </>
          ) : null}
          ; as propostas de risco alto passam por um aprovador automático, com regra fixa conferida no gabarito, e o efeito da ação é simulado. Abaixo de{" "}
          {fmtNum(indice?.confianca_minima_para_propor ?? 0.6, 1)} de confiança, os agentes só recomendam.
        </span>
      }
    />
  );
  if (carregando) {
    return (
      <>
        {cabecalho}
        <Skeleton lines={8} label="Carregando a rodada final" />
      </>
    );
  }
  if (!indice) {
    return (
      <>
        {cabecalho}
        <EmptyState icon="clipboard-check" title="Os dados da rodada final não estão neste build">
          Gere-os com python -m codigo.agente.vitrine, depois das rodadas, e rode npm run build de novo. A simulação com um pcap continua disponível.
        </EmptyState>
      </>
    );
  }
  return (
    <>
      {cabecalho}
      {indice.grupos.map((grupo) => (
        <Grupo key={grupo.id} grupo={grupo} minima={indice.confianca_minima_para_propor} atual={atual} abrir={abrir} />
      ))}
    </>
  );
}
