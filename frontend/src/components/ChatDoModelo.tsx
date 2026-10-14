import { type FormEvent, type KeyboardEvent, useEffect, useState } from "react";
import { ErroDoChat, enviarChat, listarModelos, listarPrompts, montarPedido, textoDaSkill, type MensagemDaConversa, type Prompt } from "../chat";
import { inteiro } from "../formato";

export interface PropsDaTelaDoChat {
  /** Os modelos que a pessoa pode escolher; vazio deixa o seletor desabilitado. */
  modelos: string[];
  modelo: string;
  onModelo: (modelo: string) => void;
  /** O prompt de sistema, editável; as skills só preenchem a caixa. */
  sistema: string;
  onSistema: (sistema: string) => void;
  prompts: Prompt[];
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

function linhaDeUso(mensagem: MensagemDaConversa & { papel: "assistente" }): string {
  const tokens =
    mensagem.tokens_entrada === null || mensagem.tokens_saida === null
      ? "tokens não informados"
      : `${inteiro(mensagem.tokens_entrada)} tokens de entrada · ${inteiro(mensagem.tokens_saida)} de saída`;
  const segundos = (mensagem.tempo_ms / 1000).toLocaleString("pt-BR", { maximumFractionDigits: 1 });
  return `${mensagem.modelo} · ${tokens} · ${segundos} s`;
}

/**
 * A tela do chat, sem estado: recebe a conversa e os controles e só desenha. Assim os testes a
 * desenham em qualquer estado, e o estado fica no `ChatDoModelo`.
 */
export function TelaDoChat({
  modelos,
  modelo,
  onModelo,
  sistema,
  onSistema,
  prompts,
  onCarregarPrompt,
  mensagens,
  texto,
  enviando,
  erro,
  erroDeCarga,
  onTexto,
  onEnviar,
  onLimpar,
}: PropsDaTelaDoChat) {
  const podeEnviar = !enviando && texto.trim().length > 0;
  // Sem lista (backend fora do ar), o seletor mostra o modelo atual, se houver, e fica travado.
  const opcoes = modelos.length > 0 ? modelos : modelo ? [modelo] : [];
  const enviar = (evento: FormEvent) => {
    evento.preventDefault();
    if (podeEnviar) {
      onEnviar();
    }
  };
  const tecla = (evento: KeyboardEvent<HTMLTextAreaElement>) => {
    if (evento.key === "Enter" && !evento.shiftKey) {
      evento.preventDefault();
      if (podeEnviar) {
        onEnviar();
      }
    }
  };

  return (
    <section className="chat" aria-label="Chat com o modelo">
      {erroDeCarga && (
        <div className="error-banner chat-carga" role="alert">
          <strong>Não foi possível carregar os modelos e as skills.</strong>
          <span>{erroDeCarga}</span>
        </div>
      )}
      <div className="chat-controles">
        <label className="chat-modelo">
          <span>Modelo</span>
          <select value={modelo} onChange={(evento) => onModelo(evento.target.value)} disabled={modelos.length === 0 || enviando}>
            {opcoes.map((nome) => (
              <option key={nome} value={nome}>{nome}</option>
            ))}
          </select>
        </label>
        <label className="chat-skill">
          <span>Carregar skill</span>
          {/* O valor fica sempre no marcador: escolher uma skill é uma ação, e não um estado. */}
          <select value="" onChange={(evento) => evento.target.value && onCarregarPrompt(evento.target.value)} disabled={prompts.length === 0 || enviando}>
            <option value="">Substituir o prompt de sistema por…</option>
            {prompts.map((prompt) => (
              <option key={prompt.nome} value={prompt.nome}>{prompt.titulo}</option>
            ))}
          </select>
        </label>
      </div>
      <label className="chat-sistema">
        <span>Prompt de sistema</span>
        <textarea
          value={sistema}
          onChange={(evento) => onSistema(evento.target.value)}
          disabled={enviando}
          rows={4}
          placeholder="Vazio: o modelo responde sem instruções. Carregue uma skill ou escreva as suas."
        />
      </label>
      {erro && (
        <div className="error-banner" role="alert">
          <strong>Não foi possível obter a resposta.</strong>
          <span>{erro}</span>
        </div>
      )}
      <div className="chat-conversa" aria-live="polite">
        {mensagens.length === 0 && !enviando && <p className="chat-vazia">Nenhuma mensagem ainda. Escreva abaixo e dê Enter para enviar.</p>}
        {mensagens.map((mensagem, indice) => (
          <article key={indice} className={`chat-mensagem ${mensagem.papel}`}>
            <header>{mensagem.papel === "usuario" ? "Você" : "Modelo"}</header>
            {mensagem.conteudo ? <p>{mensagem.conteudo}</p> : <p><em>O modelo não devolveu texto.</em></p>}
            {mensagem.papel === "assistente" && <footer className="chat-uso">{linhaDeUso(mensagem)}</footer>}
          </article>
        ))}
        {enviando && <p className="chat-espera">Aguardando o modelo…</p>}
      </div>
      <form className="chat-entrada" onSubmit={enviar}>
        <textarea
          value={texto}
          onChange={(evento) => onTexto(evento.target.value)}
          onKeyDown={tecla}
          disabled={enviando}
          rows={3}
          placeholder="Escreva a mensagem. Enter envia; Shift+Enter quebra a linha."
          aria-label="Mensagem para o modelo"
        />
        <div className="chat-botoes">
          <button type="button" className="chat-limpar" onClick={onLimpar} disabled={enviando}>Limpar conversa</button>
          <button type="submit" className="chat-enviar" disabled={!podeEnviar}>Enviar</button>
        </div>
      </form>
    </section>
  );
}

/** O chat com o modelo: guarda a conversa na memória da página e fala com a API por `chat.ts`. */
export default function ChatDoModelo() {
  const [modelos, setModelos] = useState<string[]>([]);
  const [modelo, setModelo] = useState("");
  const [prompts, setPrompts] = useState<Prompt[]>([]);
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

  const onCarregarPrompt = (nome: string) => setSistema((atual) => textoDaSkill(prompts, nome, atual));

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
