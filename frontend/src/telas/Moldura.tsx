import { useState, type ReactNode } from "react";
import { ASSETS, AppShell, EVENT, ReplayControl, Sidebar, type NavSection } from "../design-system";
import type { Tela } from "../rotas";
import { OPERADOR } from "./comum";
import type { PropsDaTela } from "./replay";

/** O modelo padrão do backend do chat, para o rodapé da barra lateral. Nulo enquanto carrega. */
export type ModeloDoBackend = { nome: string; online: true } | { online: false } | null;

// A navegação mostra o que existe na versão final. Ficam fora dela, acessíveis só pela âncora: a tela Ao
// vivo (`#/ao-vivo`, cortada da versão final em 02/11), o catálogo do design system (`#/componentes`,
// ferramenta da equipe) e a tela de entrada (`#/entrar`, só o visual: o SentryIoT não tem login).
function secoes(props: PropsDaTela, ativa: Tela, modoRodada: boolean): NavSection[] {
  const { estado } = props.replay;
  // A tela Ao vivo mostra outro ponto do log (ou outro log): a contagem do replay ali não vale.
  const contar = ativa !== "ao-vivo";
  return [
    {
      label: "Operação",
      items: [
        ...(modoRodada ? [{ id: "rodada", label: "Rodada final", icon: "clipboard-check" as const }] : []),
        { id: "visao-geral", label: "Visão geral", icon: "layout-dashboard" },
        { id: "incidente", label: "Incidentes", icon: "shield-alert", count: contar && estado.incidentes.length > 0 ? estado.incidentes.length : undefined, attention: contar && estado.aguardando > 0 },
        { id: "simulacao", label: "Simulação", icon: "upload" },
      ],
    },
    {
      label: "Telas do artigo",
      items: [
        { id: "isolado-integrado", label: "Isolado × integrado", icon: "columns-2" },
        { id: "custo-latencia", label: "Custo e latência", icon: "timer" },
        { id: "qualidade", label: "Qualidade do modelo", icon: "grid-3x3" },
      ],
    },
    {
      label: "Equipe",
      items: [
        { id: "relatorio", label: "Relatórios", icon: "file-text" },
        { id: "chat", label: "Chat com o modelo", icon: "messages-square" },
      ],
    },
  ];
}

function Rodape({ modelo }: { modelo: ModeloDoBackend }) {
  const texto =
    modelo === null ? (
      "Consultando o backend…"
    ) : !modelo.online ? (
      "Backend do chat fora do ar"
    ) : modelo.nome ? (
      <>
        Modelo <span className="data-sm">{modelo.nome}</span>
      </>
    ) : (
      "Backend sem modelo configurado"
    );
  return (
    <>
      <div className="sx-provmini" title="Modelo padrão do backend do chat">
        <span className={modelo?.online ? "sx-dot is-online" : "sx-dot is-offline"} />
        <span className="sx-provmini__text">{texto}</span>
      </div>
      <div className="sx-op">
        <span className="sx-op__avatar" aria-hidden="true">OP</span>
        <span className="sx-op__who">
          <span className="sx-op__name">{OPERADOR}</span>
          <span className="sx-op__role">sem login</span>
        </span>
      </div>
    </>
  );
}

export interface PropsDaMoldura extends PropsDaTela {
  ativa: Tela;
  modelo: ModeloDoBackend;
  /** O dock do pé. Sem ele, o controle do replay; `null` tira o dock. */
  dock?: ReactNode | null;
  /** A tela ocupa exatamente a altura da janela e rola por dentro (o chat). */
  cheia?: boolean;
  /** A interface abre a rodada final do build: a navegação ganha a tela dela. */
  modoRodada?: boolean;
  children: ReactNode;
}

/** A moldura de todas as telas: barra lateral, conteúdo e o controle do replay no pé. */
export function Moldura({ ativa, modelo, dock, cheia = false, modoRodada = false, children, ...props }: PropsDaMoldura) {
  const [recolhida, setRecolhida] = useState(false);
  const { replay, navegar } = props;
  const atual = replay.estado.atual;
  const controle =
    replay.estado.total > 0 ? (
      <ReplayControl
        position={Math.max(1, replay.passo)}
        total={replay.estado.total}
        onChange={replay.irPara}
        playing={replay.tocando}
        onPlayToggle={replay.alternar}
        current={atual ? { id: atual.id, label: EVENT[atual.type].label + (atual.ref ? ` · ${atual.ref}` : ""), at: atual.at } : undefined}
        marks={replay.marcas}
      />
    ) : null;
  return (
    <AppShell
      className={cheia ? "app-tela-cheia" : undefined}
      sidebar={
        <Sidebar
          logoSrc={ASSETS.mark128}
          sections={secoes(props, ativa, modoRodada)}
          activeId={ativa}
          onNavigate={(id) => navegar({ tela: id as Tela, incidente: null })}
          collapsed={recolhida}
          onToggle={() => setRecolhida((agora) => !agora)}
          footer={<Rodape modelo={modelo} />}
        />
      }
      dock={dock === undefined ? controle : dock}
    >
      {children}
    </AppShell>
  );
}
