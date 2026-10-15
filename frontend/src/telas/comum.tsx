import { useRef, useState, type ReactNode } from "react";
import { Alert, ConfirmDialog, Icon, RiskBadge, StatusBadge, TargetLabel, VoiceQuote, type Proposal } from "../design-system";
import { ErroDaOperacao, operacao } from "../operacao";

// Peças que várias telas usam: o selo de tela planejada, os avisos do log e a confirmação das
// decisões humanas.

/** Quem decide pela interface. Sem login, toda decisão sai como "operador". */
export const OPERADOR = "operador";

/** Selo das telas e dos blocos que ainda não existem de fato. */
export function Planejada({ children = "Planejada" }: { children?: ReactNode }) {
  return (
    <span className="sx-planned">
      <Icon name="clock" size={12} />
      {children}
    </span>
  );
}

/** Os avisos da leitura do log: a tela segue com o que passou na conferência. */
export function AvisosDoLog({ avisos }: { avisos: string[] }) {
  if (avisos.length === 0) {
    return null;
  }
  return (
    <Alert tone="attention" title={`O log tem ${avisos.length} ${avisos.length === 1 ? "aviso" : "avisos"}. A tela mostra só o que passou na conferência.`}>
      <ul className="app-avisos">
        {avisos.map((aviso, indice) => (
          <li key={indice}>{aviso}</li>
        ))}
      </ul>
    </Alert>
  );
}

export type PedidoDeDecisao =
  | { tipo: "approve" | "reject"; proposta: Proposal }
  | { tipo: "resolve"; incidente: string; resumo: { label: string; value: ReactNode }[] };

/** A ação nova como o agente a descreveu: o que a pessoa lê antes de aprovar, na voz do agente. */
function AcaoNova({ proposta }: { proposta: Proposal }) {
  const acao = proposta.newAction;
  if (!acao) {
    return null;
  }
  const blocos: { rotulo: string; texto: ReactNode }[] = [];
  if (acao.description) blocos.push({ rotulo: "O que faz", texto: acao.description });
  if (acao.steps) blocos.push({ rotulo: "Passos", texto: <ol className="app-passos">{acao.steps.map((passo, indice) => <li key={indice}>{passo}</li>)}</ol> });
  if (acao.expected) blocos.push({ rotulo: "Efeito esperado", texto: acao.expected });
  if (acao.undo) blocos.push({ rotulo: "Como desfazer", texto: acao.undo });
  if (acao.source) blocos.push({ rotulo: "Fonte", texto: acao.source });
  if (blocos.length === 0) {
    return null;
  }
  return (
    <>
      <span className="sx-eyebrow eyebrow">Ação nova, como o agente a descreveu</span>
      <VoiceQuote voice="agent" agent="decisao" refId={proposta.id}>
        {blocos.map((bloco) => (
          <span key={bloco.rotulo} className="app-bloco-da-acao">
            <span className="sx-eyebrow eyebrow app-rotulo-da-acao">{bloco.rotulo}</span>
            {bloco.texto}
          </span>
        ))}
      </VoiceQuote>
    </>
  );
}

/**
 * O diálogo de toda decisão humana. Confirmar chama `operacao`; quando ela não grava (hoje), o
 * diálogo fica aberto e mostra o motivo e o comando de terminal que faz a mesma coisa. Uma resposta
 * que chega depois de o diálogo fechar é descartada.
 */
export function DialogoDeDecisao({ pedido, aoFechar }: { pedido: PedidoDeDecisao | null; aoFechar: () => void }) {
  const [enviando, setEnviando] = useState(false);
  const [erro, setErro] = useState<ReactNode>(null);
  // Cada abertura e cada fechamento mudam o número: uma resposta de um pedido antigo não mexe na tela.
  const vez = useRef(0);
  const fechar = () => {
    vez.current += 1;
    setErro(null);
    setEnviando(false);
    aoFechar();
  };
  const confirmar = async (motivo: string) => {
    if (!pedido) {
      return;
    }
    const minha = ++vez.current;
    setEnviando(true);
    setErro(null);
    try {
      if (pedido.tipo === "resolve") {
        await operacao.marcarResolvido(pedido.incidente, motivo);
      } else if (pedido.tipo === "approve") {
        await operacao.aprovar(pedido.proposta.id);
      } else {
        await operacao.rejeitar(pedido.proposta.id, motivo);
      }
      if (minha === vez.current) {
        fechar();
      }
    } catch (falha) {
      if (minha !== vez.current) {
        return;
      }
      const comando = falha instanceof ErroDaOperacao ? falha.comando : null;
      setErro(
        <>
          {falha instanceof Error ? falha.message : "Falha inesperada."}
          {comando && <code className="app-comando data-sm">{comando}</code>}
        </>,
      );
    } finally {
      if (minha === vez.current) {
        setEnviando(false);
      }
    }
  };

  const proposta = pedido && pedido.tipo !== "resolve" ? pedido.proposta : null;
  const alvo = pedido?.tipo === "resolve" ? pedido.incidente : (proposta?.id ?? "");
  return (
    <ConfirmDialog
      key={`${pedido?.tipo ?? ""}:${alvo}`}
      open={pedido !== null}
      kind={pedido?.tipo ?? "approve"}
      subject={proposta ? proposta.action : alvo}
      refId={alvo}
      summary={
        proposta
          ? [
              { label: "Alvo", value: <TargetLabel label={proposta.target.label} address={proposta.target.address} free={proposta.target.free} /> },
              { label: "Prazo", value: <span className="data">{proposta.duration ?? "sem prazo"}</span> },
              { label: "Risco", value: <RiskBadge level={proposta.risk} /> },
              { label: "Estado", value: <StatusBadge kind="proposal" value={proposta.state} size="sm" /> },
            ]
          : pedido?.tipo === "resolve"
            ? pedido.resumo
            : undefined
      }
      details={proposta && pedido?.tipo === "approve" ? <AcaoNova proposta={proposta} /> : undefined}
      reasons={proposta?.reasons}
      user={OPERADOR}
      logNote={operacao.gravaDecisoes ? undefined : "A interface ainda não grava decisões: confirmar mostra o comando do terminal que faz a mesma coisa."}
      busy={enviando}
      error={erro ?? undefined}
      onCancel={fechar}
      onConfirm={confirmar}
    />
  );
}
