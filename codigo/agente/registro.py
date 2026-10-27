"""O que o laço dos agentes grava no log de eventos.

Cada chamada ao modelo vira um evento `llm_chamada` do incidente, com o agente, o modelo, os tokens
de entrada e de saída e a duração. É a base da tabela de custo e de latência do artigo.
"""

from codigo.mcp.eventos import novo


def chamadas_no_log(gravador, incidente):
    """O `ao_chamar` do laço: grava no log, em nome do agente do `gravador`, cada chamada ao modelo.

    O contrato exige contagens: se o provedor não informar `usage`, a medição é interrompida
    explicitamente, antes de executar as tools. Ausência de informação não significa custo zero.
    """

    def gravar(chamada):
        if chamada.tokens_entrada is None or chamada.tokens_saida is None:
            raise ValueError("o provedor não informou usage completo; não é possível registrar o custo em tokens")
        gravador.gravar(
            novo(
                "llm_chamada",
                {
                    "agente": gravador.agente,
                    "modelo": chamada.modelo,
                    "tokens_entrada": chamada.tokens_entrada,
                    "tokens_saida": chamada.tokens_saida,
                    "duracao_ms": chamada.duracao_ms,
                },
                incidente,
            )
        )

    return gravar
