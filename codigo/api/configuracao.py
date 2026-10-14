"""Configuração do provedor de LLM, lida do ambiente e de um arquivo `.env`."""

import os
from collections.abc import Mapping
from dataclasses import dataclass

PRAZO_PADRAO_S = 300
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
        )

    def modelos(self):
        """Os modelos permitidos, com o padrão sempre na frente."""
        return self.modelos_permitidos or (self.modelo,)

    def faltando(self):
        """Os nomes das variáveis obrigatórias que estão em branco."""
        return [variavel for variavel, atributo in OBRIGATORIAS if not getattr(self, atributo)]
