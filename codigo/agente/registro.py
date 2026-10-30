"""O que o laço dos agentes grava no log de eventos.

Cada chamada ao modelo vira um evento `llm_chamada` do incidente, com o agente, o modelo, os tokens
de entrada e de saída, a duração, o finish_reason e onde o modelo rodou. No fim do laço, um evento
`agente_concluido` diz por que ele parou, quantas voltas deu, quantos tokens gastou e, na triagem, o
veredito. É a base das tabelas de custo, de latência e de desfecho do artigo.
"""

import re

from codigo.mcp.eventos import novo
from codigo.mcp.tipos import LUGARES_DO_MODELO

# A linha "Rótulo da triagem: coerente | duvidoso | ruído" do formato da skill. Aceita o negrito do
# Markdown e recusa o modelo que só copiou o molde, com as três opções.
_ROTULO_DA_TRIAGEM = re.compile(
    r"r[óo]tulo da triagem\**\s*:\s*\**\s*(coerente|duvidoso|ru[íi]do)\b(?!\s*\|)", re.IGNORECASE
)


def chamadas_no_log(gravador, incidente, onde):
    """O `ao_chamar` do laço: grava no log, em nome do agente do `gravador`, cada chamada ao modelo.

    `onde` é `local` (o gateway) ou `nuvem`: quem sabe é o orquestrador, pela configuração que usou.
    O contrato exige contagens: se o provedor não informar `usage`, a medição é interrompida
    explicitamente, antes de executar as tools. Ausência de informação não significa custo zero.
    """
    if onde not in LUGARES_DO_MODELO:
        raise ValueError(f"onde precisa ser {' ou '.join(LUGARES_DO_MODELO)}, e veio {onde!r}")

    def gravar(chamada):
        _exigir_tokens(chamada.tokens_entrada, chamada.tokens_saida)
        termino = chamada.motivo_termino
        gravador.gravar(
            novo(
                "llm_chamada",
                {
                    "agente": gravador.agente,
                    "modelo": chamada.modelo,
                    "tokens_entrada": chamada.tokens_entrada,
                    "tokens_saida": chamada.tokens_saida,
                    "duracao_ms": chamada.duracao_ms,
                    # O finish_reason vem do JSON do provedor: o que não é texto fica nulo.
                    "motivo_termino": termino if isinstance(termino, str) and termino.strip() else None,
                    "onde": onde,
                },
                incidente,
            )
        )

    return gravar


def conclusao_no_log(gravador, incidente, resultado):
    """Grava o `agente_concluido` de um `ResultadoDoLaco`, em nome do agente do `gravador`.

    Também vale para o laço que parou num limite: o motivo vai para o log. O veredito só existe na
    triagem e só quando a resposta final traz a linha do rótulo; fora disso, fica nulo.
    """
    _exigir_tokens(resultado.tokens_entrada, resultado.tokens_saida)
    veredito = veredito_da_triagem(resultado.resposta) if gravador.agente == "triagem" else None
    return gravador.gravar(
        novo(
            "agente_concluido",
            {
                "agente": gravador.agente,
                "motivo": resultado.motivo,
                "voltas": len(resultado.chamadas_ao_modelo),
                "tokens_entrada": resultado.tokens_entrada,
                "tokens_saida": resultado.tokens_saida,
                "veredito": veredito,
            },
            incidente,
        )
    )


def veredito_da_triagem(resposta):
    """O rótulo que a triagem deu (coerente, duvidoso ou ruido), ou None se a resposta não o traz."""
    achado = _ROTULO_DA_TRIAGEM.search(resposta or "")
    if achado is None:
        return None
    return achado.group(1).lower().replace("í", "i")


def _exigir_tokens(entrada, saida):
    if entrada is None or saida is None:
        raise ValueError("o provedor não informou usage completo; não é possível registrar o custo em tokens")
