import { useEffect, useState } from "react";
import { ondeRoda, provedoresDoChat } from "../adaptador";
import { ErroDoChat, enviarChat, listarModelos, listarPrompts, montarPedido, textoDaSkill, type MensagemDaConversa, type Prompt } from "../chat";
import { Alert, Button, ChatMessage, EmptyState, ModelSelect, PageHeader, Panel, PromptBox, ProviderBar, Select, Skeleton, TextField, fmtInt } from "../design-system";

/** Estimativa grosseira de tokens: cerca de quatro caracteres por token. */
export function estimarTokens(texto: string): number {
  return Math.ceil(texto.length / 4);
}

export interface PropsDaTelaDoChat {
  /** Os modelos que a pessoa pode escolher; vazio deixa o seletor desabilitado. */
  modelos: string[];
  modelo: string;
  onModelo: (modelo: string) => void;
  /** O prompt de sistema, editável; as skills só preenchem a caixa. */
  sistema: string;
  onSistema: (sistema: string) => void;
  prompts: Prompt[];
  /** A última skill carregada, para "Restaurar o padrão da skill". */
  skill: string;
  onCarregarPrompt: (nome: string) => void;
  mensagens: MensagemDaConversa[];
  texto: string;
  enviando: boolean;
  /** Erro do último envio; some no próximo envio ou ao limpar. */
  erro: string | null;
  /** Falha ao carregar modelos ou skills na abertura; fica até recarregar a página. */
  erroDeCarga: string | null;
  onTexto: (texto: string) => void;
  onEnviar: () => void;
  onLimpar: () => void;
}

function Mensagem({ mensagem }: { mensagem: MensagemDaConversa }) {
  if (mensagem.papel === "usuario") {
    return <ChatMessage role="user">{mensagem.conteudo}</ChatMessage>;
  }
  const informados = mensagem.tokens_entrada !== null && mensagem.tokens_saida !== null;
  return (
    <>
      <ChatMessage
        role="assistant"
        author={mensagem.modelo}
        location={ondeRoda(mensagem.modelo)}
        tokens={informados ? mensagem.tokens_entrada! + mensagem.tokens_saida! : null}
        tokensDetail={informados ? `${fmtInt(mensagem.tokens_entrada!)} de entrada · ${fmtInt(mensagem.tokens_saida!)} de saída` : undefined}
        seconds={mensagem.tempo_ms / 1000}
      >
        {mensagem.conteudo}
      </ChatMessage>
      {!mensagem.conteudo && <ChatMessage role="system">O modelo não devolveu texto.</ChatMessage>}
    </>
  );
}

/**
 * A tela do chat, sem estado: recebe a conversa e os controles e só desenha. Assim os testes a
 * desenham em qualquer estado, e o estado fica no `ChatDoModelo`.
 */
export function TelaDoChat(props: PropsDaTelaDoChat) {
  const { modelos, modelo, onModelo, sistema, onSistema, prompts, skill, onCarregarPrompt, mensagens, texto, enviando, erro, erroDeCarga, onTexto, onEnviar, onLimpar } = props;
  // Sem lista (backend fora do ar), o seletor mostra o modelo atual, se houver, e fica travado.
  const provedores = provedoresDoChat(modelos.length > 0 ? modelos : modelo ? [modelo] : []).map((provedor) =>
    modelos.length > 0 ? provedor : { ...provedor, status: "offline" as const },
  );
  const enviar = () => {
    if (!enviando && texto.trim().length > 0) {
      onEnviar();
    }
  };
  const titulo = prompts.find((prompt) => prompt.nome === skill)?.titulo;

  return (
    <>
      <PageHeader
        eyebrow="Equipe"
        title="Chat com o modelo"
        meta={<span className="body-sm sx-muted">Ferramenta da equipe para testar prompts e as skills dos agentes. Não grava no log de eventos e não entra na banca.</span>}
      />
      {erroDeCarga && (
        <Alert tone="danger" title="Não foi possível carregar os modelos e as skills.">
          {erroDeCarga}
        </Alert>
      )}
      <ProviderBar
        providers={provedores}
        selectedId={modelo}
        onSelect={onModelo}
        disabled={enviando}
        note="O chat manda ao modelo o que você escrever: não cole endereços reais."
      />
      <div className="sx-grid">
        <Panel className="sx-span-4" eyebrow="Configuração" title="Modelo e prompt">
          <div className="sx-stack sx-stack--sm">
            <span className="sx-eyebrow eyebrow">Modelo</span>
            <ModelSelect providers={provedores} value={modelo} onChange={onModelo} disabled={enviando || modelos.length === 0} />
            <Select
              label="Carregar skill de agente"
              value=""
              disabled={prompts.length === 0 || enviando}
              onChange={(nome) => nome && onCarregarPrompt(nome)}
              options={[
                { value: "", label: prompts.length > 0 ? "Substituir o prompt de sistema por…" : "Nenhuma skill disponível" },
                ...prompts.map((prompt) => ({ value: prompt.nome, label: prompt.titulo })),
              ]}
              hint={titulo ? `Carregada: ${titulo}` : undefined}
            />
            <TextField
              label="Prompt de sistema"
              multiline
              rows={10}
              mono
              value={sistema}
              disabled={enviando}
              onChange={(evento) => onSistema(evento.target.value)}
              placeholder="Vazio: o modelo responde sem instruções. Carregue uma skill ou escreva as suas."
              hint={`≈ ${fmtInt(estimarTokens(sistema))} tokens · fica só nesta página`}
            />
            <Button variant="ghost" icon="rotate-ccw" disabled={!skill || enviando} onClick={() => onCarregarPrompt(skill)}>
              Restaurar o padrão da skill
            </Button>
          </div>
        </Panel>
        <Panel
          className="sx-span-8"
          eyebrow="Conversa"
          title={`${titulo ?? "Sem skill"} · ${modelo || "sem modelo"}`}
          actions={
            <Button variant="ghost" size="sm" icon="x" onClick={onLimpar} disabled={enviando || mensagens.length === 0}>
              Limpar conversa
            </Button>
          }
        >
          <div className="sx-stack">
            {erro && (
              <Alert tone="danger" title="Não foi possível obter a resposta.">
                {erro}
              </Alert>
            )}
            <div className="sx-chatlog" aria-live="polite">
              {mensagens.length === 0 && !enviando && (
                <EmptyState icon="messages-square" title="Nenhuma mensagem ainda">
                  Escreva abaixo e tecle Enter para enviar. Shift+Enter quebra a linha.
                </EmptyState>
              )}
              {mensagens.map((mensagem, indice) => (
                <Mensagem key={indice} mensagem={mensagem} />
              ))}
              {enviando && <Skeleton lines={3} label="Aguardando o modelo" />}
            </div>
            <PromptBox
              value={texto}
              onChange={onTexto}
              onSend={enviar}
              disabled={enviando}
              tokens={texto ? estimarTokens(texto) : undefined}
              placeholder="Escreva a mensagem. Enter envia; Shift+Enter quebra a linha."
              tools={<ModelSelect providers={provedores} value={modelo} onChange={onModelo} compact disabled={enviando || modelos.length === 0} />}
            />
          </div>
        </Panel>
      </div>
    </>
  );
}

/** O chat com o modelo: guarda a conversa na memória da página e fala com a API por `chat.ts`. */
export function ChatDoModelo() {
  const [modelos, setModelos] = useState<string[]>([]);
  const [modelo, setModelo] = useState("");
  const [prompts, setPrompts] = useState<Prompt[]>([]);
  const [skill, setSkill] = useState("");
  const [sistema, setSistema] = useState("");
  const [mensagens, setMensagens] = useState<MensagemDaConversa[]>([]);
  const [texto, setTexto] = useState("");
  const [enviando, setEnviando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [erroDeCarga, setErroDeCarga] = useState<string | null>(null);

  useEffect(() => {
    let ativo = true;
    const avisar = (falha: unknown, padrao: string) => {
      if (ativo) {
        setErroDeCarga(falha instanceof ErroDoChat ? falha.message : padrao);
      }
    };
    listarModelos()
      .then((lista) => {
        if (ativo) {
          setModelos(lista.modelos);
          setModelo(lista.padrao);
        }
      })
      .catch((falha: unknown) => avisar(falha, "Falha inesperada ao listar os modelos."));
    listarPrompts()
      .then((lista) => {
        if (ativo) {
          setPrompts(lista);
        }
      })
      .catch((falha: unknown) => avisar(falha, "Falha inesperada ao listar as skills."));
    return () => {
      ativo = false;
    };
  }, []);

  const onCarregarPrompt = (nome: string) => {
    setSistema((atual) => textoDaSkill(prompts, nome, atual));
    if (prompts.some((prompt) => prompt.nome === nome)) {
      setSkill(nome);
    }
  };

  const onEnviar = async () => {
    if (!texto.trim() || enviando) {
      return;
    }
    const { historico, pedido } = montarPedido(mensagens, texto, modelo, sistema);
    setMensagens(historico);
    setTexto("");
    setErro(null);
    setEnviando(true);
    try {
      const resposta = await enviarChat(pedido);
      setMensagens([...historico, { papel: "assistente", ...resposta }]);
    } catch (falha) {
      // A mensagem volta para a caixa: a pessoa corrige ou tenta de novo sem redigitar.
      setMensagens(mensagens);
      setTexto(texto);
      setErro(falha instanceof ErroDoChat ? falha.message : "Falha inesperada ao falar com o backend.");
    } finally {
      setEnviando(false);
    }
  };

  const onLimpar = () => {
    setMensagens([]);
    setErro(null);
  };

  return (
    <TelaDoChat
      modelos={modelos}
      modelo={modelo}
      onModelo={setModelo}
      sistema={sistema}
      onSistema={setSistema}
      prompts={prompts}
      skill={skill}
      onCarregarPrompt={onCarregarPrompt}
      mensagens={mensagens}
      texto={texto}
      enviando={enviando}
      erro={erro}
      erroDeCarga={erroDeCarga}
      onTexto={setTexto}
      onEnviar={onEnviar}
      onLimpar={onLimpar}
    />
  );
}
