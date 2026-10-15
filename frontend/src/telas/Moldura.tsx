import { useState, type ReactNode } from "react";
import { ASSETS, AppShell, EVENT, IconButton, ReplayControl, Sidebar, type NavSection } from "../design-system";
import type { Tela } from "../rotas";
import { OPERADOR } from "./comum";
import type { PropsDaTela } from "./replay";

/** O modelo padrão do backend do chat, para o rodapé da barra lateral. Nulo enquanto carrega. */
export type ModeloDoBackend = { nome: string; online: true } | { online: false } | null;

const AO_VIVO_CONFIGURADO = Boolean(import.meta.env.VITE_LOG_AO_VIVO);

function secoes(props: PropsDaTela, ativa: Tela): NavSection[] {
  const { estado } = props.replay;
  // A tela Ao vivo mostra outro ponto do log (ou outro log): a contagem do replay ali não vale.
  const contar = ativa !== "ao-vivo";
  return [
    {
      label: "Operação",
      items: [
        { id: "visao-geral", label: "Visão geral", icon: "layout-dashboard" },
        { id: "incidente", label: "Incidentes", icon: "shield-alert", count: contar ? estado.incidentes.length : undefined, attention: contar && estado.aguardando > 0 },
        { id: "ao-vivo", label: "Ao vivo", icon: "radio", planned: !AO_VIVO_CONFIGURADO },
      ],
    },
    {
      label: "Telas do artigo",
      items: [
        { id: "isolado-integrado", label: "Isolado × integrado", icon: "columns-2" },
        { id: "custo-latencia", label: "Custo e latência", icon: "timer" },
        { id: "qualidade", label: "Qualidade do modelo", icon: "grid-3x3" },
        { id: "seguranca-mcp", label: "Segurança do MCP", icon: "shield-check", planned: true },
      ],
    },
    {
      label: "Equipe",
      items: [
        { id: "chat", label: "Chat com o modelo", icon: "messages-square" },
        { id: "relatorio", label: "Relatórios", icon: "file-text" },
        { id: "componentes", label: "Componentes", icon: "layers" },
      ],
    },
  ];
}

function Rodape({ modelo, navegar }: { modelo: ModeloDoBackend; navegar: PropsDaTela["navegar"] }) {
  const texto =
    modelo === null ? "Consultando o backend…" : modelo.online ? <>Modelo <span className="data-sm">{modelo.nome}</span></> : "Backend do chat fora do ar";
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
        <IconButton icon="log-in" label="Entrar" variant="ghost" size="sm" onClick={() => navegar({ tela: "entrar", incidente: null })} />
      </div>
    </>
  );
}

export interface PropsDaMoldura extends PropsDaTela {
  ativa: Tela;
  modelo: ModeloDoBackend;
  /** O dock do pé. Sem ele, o controle do replay; `null` tira o dock. */
  dock?: ReactNode | null;
  children: ReactNode;
}

/** A moldura de todas as telas: barra lateral, conteúdo e o controle do replay no pé. */
export function Moldura({ ativa, modelo, dock, children, ...props }: PropsDaMoldura) {
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
      sidebar={
        <Sidebar
          logoSrc={ASSETS.mark128}
          sections={secoes(props, ativa)}
          activeId={ativa}
          onNavigate={(id) => navegar({ tela: id as Tela, incidente: null })}
          collapsed={recolhida}
          onToggle={() => setRecolhida((agora) => !agora)}
          footer={<Rodape modelo={modelo} navegar={navegar} />}
        />
      }
      dock={dock === undefined ? controle : dock}
    >
      {children}
    </AppShell>
  );
}
