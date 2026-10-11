import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  /** O que não pôde ser mostrado, para a mensagem. */
  parte: string;
  /** Quando muda (outro incidente, por exemplo), a parte é desenhada de novo. */
  chave: string;
  children: ReactNode;
}

interface Estado {
  erro: Error | null;
}

/**
 * Error boundary: um erro ao desenhar a fila ou o detalhe fica restrito a essa parte da tela. Sem
 * ele, o React desmonta a árvore inteira e a tela fica em branco.
 */
export default class LimiteDeErro extends Component<Props, Estado> {
  state: Estado = { erro: null };

  static getDerivedStateFromError(erro: Error): Estado {
    return { erro };
  }

  componentDidCatch(erro: Error, info: ErrorInfo) {
    console.error(`Erro ao mostrar ${this.props.parte}:`, erro, info.componentStack);
  }

  componentDidUpdate(anteriores: Props) {
    if (this.state.erro && anteriores.chave !== this.props.chave) {
      this.setState({ erro: null });
    }
  }

  render() {
    if (this.state.erro) {
      return (
        <div className="error-banner" role="alert">
          <strong>Não foi possível mostrar {this.props.parte}.</strong>
          <span>{this.state.erro.message}</span>
        </div>
      );
    }
    return this.props.children;
  }
}
