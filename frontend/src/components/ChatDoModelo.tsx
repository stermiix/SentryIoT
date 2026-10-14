import { type FormEvent, type KeyboardEvent, useState } from "react";
import { ErroDoChat, enviarChat, montarPedido, type MensagemDaConversa } from "../chat";
import { inteiro } from "../formato";

export interface PropsDaTelaDoChat {
  mensagens: MensagemDaConversa[];
  texto: string;
  enviando: boolean;
  erro: string | null;
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
export function TelaDoChat({ mensagens, texto, enviando, erro, onTexto, onEnviar, onLimpar }: PropsDaTelaDoChat) {
  const podeEnviar = !enviando && texto.trim().length > 0;
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
  const [mensagens, setMensagens] = useState<MensagemDaConversa[]>([]);
  const [texto, setTexto] = useState("");
  const [enviando, setEnviando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);

  const onEnviar = async () => {
    if (!texto.trim() || enviando) {
      return;
    }
    const { historico, pedido } = montarPedido(mensagens, texto);
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

  return <TelaDoChat mensagens={mensagens} texto={texto} enviando={enviando} erro={erro} onTexto={setTexto} onEnviar={onEnviar} onLimpar={onLimpar} />;
}
