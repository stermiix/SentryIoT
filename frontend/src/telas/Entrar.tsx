import { useState, type FormEvent } from "react";
import { ASSETS, Alert, Button, GlassBackdrop, Icon, Logo, TextField } from "../design-system";
import { ErroDaOperacao, operacao } from "../operacao";
import type { Rota } from "../rotas";

/**
 * A entrada do operador, com a marca de vidro ao fundo. O login ainda não existe: "Entrar" passa
 * por `operacao.entrar`, que hoje explica isso, e "Abrir o replay" leva à visão geral.
 */
export function TelaEntrar({ navegar }: { navegar: (rota: Rota) => void }) {
  const [usuario, setUsuario] = useState("");
  const [senha, setSenha] = useState("");
  const [entrando, setEntrando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);

  const entrar = async (evento: FormEvent<HTMLFormElement>) => {
    evento.preventDefault();
    setEntrando(true);
    setErro(null);
    try {
      await operacao.entrar(usuario, senha);
      navegar({ tela: "visao-geral", incidente: null });
    } catch (falha) {
      setErro(falha instanceof ErroDaOperacao || falha instanceof Error ? falha.message : "Falha inesperada ao entrar.");
    } finally {
      setEntrando(false);
    }
  };

  return (
    <div className="sx-login">
      <GlassBackdrop src={ASSETS.mark} variant="login" />
      <div className="sx-login__inner">
        <header className="sx-login__top">
          <div className="sx-login__brand">
            <Logo src={ASSETS.mark128} size="lg" />
            <div className="sx-login__tagline sx-wide eyebrow-wide">
              Detecção e resposta
              <br />a intrusões em redes IoT
            </div>
          </div>
          <div className="sx-login__kicker">
            <div className="sx-login__kickline sx-wide eyebrow-wide">
              Acesso do operador
              <span className="sx-cover__dash" />
            </div>
            <div className="sx-wide eyebrow-wide">
              Detecta.
              <br />
              Responde.
            </div>
          </div>
        </header>

        <main className="sx-login__center">
          <span className="sx-accent-bar" />
          <div className="sx-login__eyebrow sx-wide eyebrow-wide">Resposta autônoma a intrusão</div>
          <h1 className="sx-login__title display-lg">Entrar</h1>
          <form className="sx-login__card" onSubmit={entrar}>
            {erro && (
              <Alert tone={operacao.temLogin ? "danger" : "attention"} title={operacao.temLogin ? "Não foi possível entrar" : "Login ainda não disponível"}>
                {erro}
              </Alert>
            )}
            <TextField label="Usuário" icon="user" placeholder="ex.: operador" autoComplete="username" size="lg" value={usuario} onChange={(e) => setUsuario(e.target.value)} />
            <TextField label="Senha" type="password" icon="lock" placeholder="••••••••" autoComplete="current-password" size="lg" value={senha} onChange={(e) => setSenha(e.target.value)} />
            <Button type="submit" variant="primary" size="lg" block iconRight="arrow-right" loading={entrando}>
              Entrar
            </Button>
            <div className="sx-login__or data-sm">ou</div>
            <Button variant="secondary" size="lg" block icon="history" onClick={() => navegar({ tela: "visao-geral", incidente: null })}>
              Abrir o replay
            </Button>
          </form>
          <div className="sx-login__status data-sm">
            <span>O replay funciona sem internet</span>
            <span>TCC 2026</span>
          </div>
        </main>

        <footer className="sx-login__foot">
          <div className="sx-login__copy sx-wide data-sm">© 2026 SentryIoT · Ciência da Computação · Mackenzie</div>
          <div className="sx-login__seal">
            <div className="sx-seal">
              <Icon name="lock" size={18} />
              <span className="sx-seal__bar" />
              <span className="sx-seal__text">Acesso restrito</span>
            </div>
            <div className="sx-login__sealnote sx-wide data-sm">
              Uso da equipe e
              <br />
              da banca avaliadora.
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}
