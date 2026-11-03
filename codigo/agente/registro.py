"""O que o laço dos agentes grava no log de eventos.

Cada chamada ao modelo vira um evento `llm_chamada` do incidente, com o agente, o modelo, os tokens
de entrada e de saída, a duração, o finish_reason e onde o modelo rodou. No fim do laço, um evento
`conversa_do_agente` guarda o que o agente recebeu e respondeu, e um `agente_concluido` diz por que ele
parou, quantas voltas deu, quantos tokens gastou e, na triagem, o veredito. É a base das tabelas de
custo, de latência e de desfecho do artigo, e da conversa que a interface mostra em cada incidente.
"""

import re

from codigo.mcp.eventos import novo
from codigo.mcp.tipos import (
    LUGARES_DO_MODELO,
    MAIOR_TEXTO_DA_CONVERSA,
    MAXIMO_DE_MENSAGENS_DA_CONVERSA,
    MAXIMO_DE_TOOLS_PEDIDAS,
    TEXTO_CURTO,
    invisivel,
)

# Os papéis de mensagem que a conversa guarda; outro papel (que a API não usa aqui) vira user.
_PAPEIS = ("system", "user", "assistant", "tool")

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


def conversa_no_log(gravador, incidente, resultado, *, modelo, onde, tarefa="incidente"):
    """Grava o `conversa_do_agente` de um `ResultadoDoLaco`: o histórico inteiro, em nome do agente.

    O texto vai como veio, com duas exceções que o contrato pede: o caractere que não aparece na tela vira
    a sequência de escape dele (a tabulação vira espaços), e o que passa do tamanho máximo é cortado, com o
    aviso do corte no próprio texto. Gravar a conversa nunca muda o que o agente fez. `tarefa` separa o
    trabalho do agente no incidente do sumário que a triagem escreve no fim (`sumario.py`).
    """
    if onde not in LUGARES_DO_MODELO:
        raise ValueError(f"onde precisa ser {' ou '.join(LUGARES_DO_MODELO)}, e veio {onde!r}")
    mensagens = [_mensagem_da_conversa(mensagem) for mensagem in resultado.mensagens]
    if len(mensagens) > MAXIMO_DE_MENSAGENS_DA_CONVERSA:
        # O começo (sistema e pedido) e o fim (a resposta) são o que importa; o meio sai, com o aviso.
        fim = MAXIMO_DE_MENSAGENS_DA_CONVERSA - 3
        omitidas = len(mensagens) - 2 - fim
        aviso = {"papel": "user", "texto": f"[{omitidas} mensagens do meio da conversa omitidas no log]", "tools_pedidas": []}
        mensagens = [*mensagens[:2], aviso, *mensagens[-fim:]]
    return gravador.gravar(
        novo(
            "conversa_do_agente",
            {
                "agente": gravador.agente,
                "modelo": _uma_linha(modelo),
                "tarefa": tarefa,
                "onde": onde,
                "motivo": resultado.motivo,
                "mensagens": mensagens,
            },
            incidente,
        )
    )


def _mensagem_da_conversa(mensagem):
    papel = mensagem.get("role") if isinstance(mensagem, dict) else None
    papel = papel if papel in _PAPEIS else "user"
    conteudo = mensagem.get("content") if isinstance(mensagem, dict) else None
    saida = {"papel": papel, "texto": _texto_da_conversa(_conteudo_em_texto(conteudo)), "tools_pedidas": []}
    if papel == "assistant":
        pedidas = mensagem.get("tool_calls") or []
        saida["tools_pedidas"] = [_tool_pedida(pedida) for pedida in pedidas[:MAXIMO_DE_TOOLS_PEDIDAS]]
    if papel == "tool":
        resposta_a = _cortar(_limpar(str(mensagem.get("tool_call_id") or "")).replace("\n", " "), TEXTO_CURTO).strip()
        saida["resposta_a"] = resposta_a or None
    return saida


def _tool_pedida(pedida):
    funcao = pedida.get("function") if isinstance(pedida, dict) else None
    funcao = funcao if isinstance(funcao, dict) else {}
    argumentos = funcao.get("arguments")
    if not isinstance(argumentos, str):
        argumentos = "" if argumentos is None else str(argumentos)
    return {
        "id": _uma_linha(pedida.get("id") if isinstance(pedida, dict) else None),
        "nome": _uma_linha(funcao.get("name")),
        "argumentos": _texto_da_conversa(argumentos),
    }


def _conteudo_em_texto(conteudo):
    """O `content` da API em texto: string, nulo (só tools) ou a lista de partes de texto."""
    if conteudo is None:
        return ""
    if isinstance(conteudo, str):
        return conteudo
    if isinstance(conteudo, list):
        return "\n".join(str(parte.get("text", "")) for parte in conteudo if isinstance(parte, dict))
    return str(conteudo)


def _limpar(texto):
    """Troca o que não aparece na tela pela sequência de escape; a tabulação vira espaços, e \\r\\n vira \\n."""
    texto = str(texto).replace("\r\n", "\n").replace("\t", "    ")
    return "".join(letra.encode("unicode_escape").decode("ascii") if invisivel(letra) else letra for letra in texto)


def _cortar(texto, maximo):
    if len(texto) <= maximo:
        return texto
    aviso = f"\n[cortado no log: {len(texto) - maximo} caracteres a mais]"
    return texto[: maximo - len(aviso)] + aviso


def _texto_da_conversa(texto):
    return _cortar(_limpar(texto), MAIOR_TEXTO_DA_CONVERSA)


def _uma_linha(valor):
    texto = _cortar(_limpar("" if valor is None else str(valor)).replace("\n", " "), TEXTO_CURTO).strip()
    return texto or "?"
