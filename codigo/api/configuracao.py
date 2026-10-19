"""Configuração do provedor de LLM, lida do ambiente e de um arquivo `.env`."""

import os
from collections.abc import Mapping
from dataclasses import dataclass

PRAZO_PADRAO_S = 300
# Valores de LLM_RACIOCINIO e o que cada um manda em `chat_template_kwargs.enable_thinking`.
RACIOCINIO = {"ligado": True, "desligado": False}
# Variável obrigatória do ambiente e o atributo que a guarda, na ordem em que `faltando` relata.
OBRIGATORIAS = (("LLM_BASE_URL", "url_base"), ("LLM_API_KEY", "chave"), ("LLM_MODEL", "modelo"))


def carregar_env(caminho):
    """Lê `CHAVE=valor` de um `.env`, sem sobrescrever variável já definida no ambiente.

    Linhas em branco, comentários e linhas sem `=` são ignoradas; aspas simples ou duplas em
    volta do valor são retiradas. Arquivo inexistente não é erro: a configuração pode vir toda
    do ambiente.
    """
    if not os.path.exists(caminho):
        return
    with open(caminho, encoding="utf-8") as arquivo:
        for linha in arquivo:
            linha = linha.strip()
            if not linha or linha.startswith("#") or "=" not in linha:
                continue
            chave, valor = linha.split("=", 1)
            os.environ.setdefault(chave.strip(), valor.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Configuracao:
    url_base: str
    chave: str
    modelo: str
    ca: str | None = None
    prazo_s: float = PRAZO_PADRAO_S
    # Os modelos que a interface pode escolher. Vazio quer dizer só o padrão (ver `modelos`).
    modelos_permitidos: tuple[str, ...] = ()
    # Parâmetros de geração mandados em toda chamada, quando definidos; sem a variável, vale o
    # padrão do provedor. O raciocínio vai em `chat_template_kwargs`, que o llama.cpp e o vLLM
    # entendem; no gateway de 19/10, desligá-lo deixou a triagem 30% mais rápida, com os mesmos rótulos.
    temperatura: float | None = None
    semente: int | None = None
    max_tokens: int | None = None
    raciocinio: bool | None = None

    @classmethod
    def do_ambiente(cls, ambiente: Mapping[str, str]):
        prazo = ambiente.get("LLM_TIMEOUT_S", "").strip()
        modelo = ambiente.get("LLM_MODEL", "").strip()
        listados = [nome.strip() for nome in ambiente.get("LLM_MODELOS_PERMITIDOS", "").split(",")]
        permitidos = tuple(dict.fromkeys([modelo, *listados]))
        return cls(
            url_base=ambiente.get("LLM_BASE_URL", "").strip().rstrip("/"),
            chave=ambiente.get("LLM_API_KEY", "").strip(),
            modelo=modelo,
            ca=ambiente.get("LLM_CA_BUNDLE", "").strip() or None,
            prazo_s=float(prazo) if prazo else PRAZO_PADRAO_S,
            modelos_permitidos=tuple(nome for nome in permitidos if nome),
            temperatura=_numero(ambiente, "LLM_TEMPERATURA", float, 0, 2),
            semente=_numero(ambiente, "LLM_SEMENTE", int, 0, None),
            max_tokens=_numero(ambiente, "LLM_MAX_TOKENS", int, 1, None),
            raciocinio=_raciocinio(ambiente),
        )

    def parametros(self):
        """Os parâmetros de geração definidos, já com os nomes do corpo de `chat/completions`."""
        corpo = {}
        if self.temperatura is not None:
            corpo["temperature"] = self.temperatura
        if self.semente is not None:
            corpo["seed"] = self.semente
        if self.max_tokens is not None:
            corpo["max_tokens"] = self.max_tokens
        if self.raciocinio is not None:
            corpo["chat_template_kwargs"] = {"enable_thinking": self.raciocinio}
        return corpo

    def modelos(self):
        """Os modelos permitidos, com o padrão sempre na frente, venha a lista de onde vier."""
        return tuple(nome for nome in dict.fromkeys([self.modelo, *self.modelos_permitidos]) if nome)

    def faltando(self):
        """Os nomes das variáveis obrigatórias que estão em branco."""
        return [variavel for variavel, atributo in OBRIGATORIAS if not getattr(self, atributo)]


def _numero(ambiente, variavel, tipo, minimo, maximo):
    """O número de uma variável opcional, ou None quando ela está em branco. Fora da faixa é erro."""
    texto = ambiente.get(variavel, "").strip()
    if not texto:
        return None
    try:
        valor = tipo(texto)
    except ValueError:
        raise ValueError(f"{variavel} precisa ser um número{' inteiro' if tipo is int else ''}, e veio {texto!r}") from None
    if valor < minimo or (maximo is not None and valor > maximo):
        faixa = f"entre {minimo} e {maximo}" if maximo is not None else f"a partir de {minimo}"
        raise ValueError(f"{variavel} precisa estar {faixa}, e veio {texto}")
    return valor


def _raciocinio(ambiente):
    texto = ambiente.get("LLM_RACIOCINIO", "").strip().lower()
    if not texto:
        return None
    if texto not in RACIOCINIO:
        raise ValueError(f"LLM_RACIOCINIO precisa ser ligado ou desligado, e veio {texto!r}")
    return RACIOCINIO[texto]
