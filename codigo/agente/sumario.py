"""O sumário do incidente, escrito pelo agente de triagem quando o orquestrador termina.

É a seção "Sumário" do relatório do incidente (decisão de 2026-10-31). O texto sai do modelo da triagem,
numa chamada só e sem tools, a partir dos fatos do log, que este módulo junta em texto: o que o
classificador disse, a análise da triagem, o atacante apontado, as recomendações, as propostas, as
decisões das pessoas, as execuções e os efeitos. A chamada vai para o log como `llm_chamada` da triagem,
e o texto como `sumario_emitido`. O sumário não tem `agente_concluido` próprio: não é outra triagem.
"""

from codigo.agente.laco import rodar
from codigo.agente.registro import chamadas_no_log
from codigo.mcp.acoes import reconstruir
from codigo.mcp.eventos import GravadorDoAgente, ler, novo
from codigo.mcp.tipos import TEXTO_LONGO

SISTEMA_DO_SUMARIO = (
    "Você é o agente de triagem do SentryIoT, um sistema de detecção e resposta a ataques em redes IoT. O "
    "incidente terminou no orquestrador. Escreva o sumário dele para a pessoa que opera a rede, em português, "
    "num parágrafo de 3 a 6 frases: o que o classificador detectou e com que confiança, o que a triagem "
    "concluiu e quem ela apontou como atacante, o que o agente de decisão propôs, o que a pessoa decidiu e por "
    "quê, o que foi executado e o efeito verificado. Use só os fatos dados, sem inventar número, endereço, "
    "decisão ou ação: o que não está nos fatos não aconteceu. Termine pelo desfecho, como os fatos o dizem. "
    "Sem títulos e sem listas."
)
# Como o orquestrador terminou, nas palavras do sumário. As chaves são os desfechos de `agentes.py`.
DESFECHOS = {
    "resolvido": "a ação aplicada fez o ataque cessar, e o incidente foi resolvido",
    "sem_resolucao": "as rodadas da decisão acabaram sem o ataque cessar",
    "agente_parou": "um agente parou antes de terminar, num limite do laço ou numa falha do modelo",
    "sem_proposta": "o agente de decisão não propôs ação",
    "sem_aprovacao": "a proposta de risco alto ficou esperando uma pessoa, e a espera acabou sem decisão",
    "todas_rejeitadas": "a pessoa rejeitou as propostas, e nenhuma ação foi aplicada",
    "efeito_nao_verificado": "a ação foi aplicada, mas o efeito não foi verificado",
}
ABERTURA_DO_SUMARIO = "Os fatos do incidente {incidente}, tirados do log de eventos:\n\n{fatos}\n\nEscreva o sumário."
# Os textos dos agentes entram cortados nos fatos: o sumário não precisa deles inteiros.
MAIOR_TEXTO_CITADO = 1200


def _cortado(texto, maximo=MAIOR_TEXTO_CITADO):
    texto = " ".join(str(texto).split())
    return texto if len(texto) <= maximo else texto[: maximo - 1].rstrip() + "…"


def _lista(itens):
    return ", ".join(f"{item.endereco} ({item.quadros} quadros)" for item in itens[:3]) or "nenhum"


def fatos_do_incidente(eventos, incidente, desfecho=None):
    """Os fatos do incidente no log, em linhas de texto, na ordem em que aconteceram, e o que não aconteceu.

    O modelo tende a completar a história (a proposta foi aprovada, a ação foi aplicada): por isso os
    fatos dizem também o que não aconteceu e terminam pelo desfecho do orquestrador, quando ele vem.
    """
    estado = reconstruir(eventos)
    if incidente not in estado.incidentes:
        raise ValueError(f"o incidente {incidente} não existe no log")
    dados = estado.incidentes[incidente]
    por_categoria = ", ".join(f"{categoria} {n}" for categoria, n in dados.janelas_por_categoria.items())
    linhas = [
        f"Classificador: {dados.categoria} (o modelo disse {dados.categoria_do_modelo}), confiança média "
        f"{dados.confianca:.2f}, {dados.janelas} janelas de ataque"
        + (f" (janelas por categoria: {por_categoria})" if por_categoria else "")
        + f", {dados.origens_distintas} origens distintas, estado {dados.estado}.",
        f"Origens com mais quadros: {_lista(dados.origens)}. Destinos: {_lista(dados.destinos)}.",
    ]
    if dados.portas:
        portas = ", ".join(f"{p.porta}/{p.protocolo} em {p.destino}" for p in dados.portas[:3])
        linhas.append(f"Portas mais atacadas: {portas}.")
    for evento in eventos:
        if evento.incidente != incidente:
            continue
        d = evento.dados
        match evento.tipo:
            case "incidente_marcado_resolvido":
                linhas.append(f"A pessoa ({d.usuario}) marcou o incidente como já resolvido: {d.motivo or 'sem motivo escrito'}.")
            case "analise_emitida":
                linhas.append(f"Análise da triagem (rótulo {d.veredito or 'não dito'}): {_cortado(d.texto)}")
            case "atacante_apontado":
                linhas.append(f"A triagem apontou {d.endereco} como atacante: {_cortado(d.justificativa, 400)}")
            case "recomendacao_emitida":
                linhas.append(f"Recomendação do agente de decisão: {_cortado(d.texto)}")
            case "acao_proposta":
                aprovacao = "exige aprovação humana" if d.exige_aprovacao else "liberada sem aprovação"
                linhas.append(f"Proposta {d.id}: {d.acao} em {d.alvo}, risco {d.risco}, {aprovacao}.")
            case "acao_aprovada" | "acao_rejeitada":
                verbo = "aprovou" if evento.tipo == "acao_aprovada" else "rejeitou"
                motivo = f": {_cortado(d.motivo, 300)}" if d.motivo else ", sem motivo escrito"
                linhas.append(f"A pessoa ({d.usuario}) {verbo} a proposta {d.proposta}{motivo}.")
            case "acao_executada":
                linhas.append(f"Execução {d.id}: {d.acao} em {d.alvo} aplicada.")
            case "acao_desfeita":
                linhas.append(f"Execução {d.id} desfeita.")
            case "efeito_verificado":
                linhas.append(f"Efeito verificado da execução {d.execucao}: {d.resultado}.")
    tipos = {evento.tipo for evento in eventos if evento.incidente == incidente}
    if not any(proposta.incidente == incidente for proposta in estado.propostas.values()):
        linhas.append("Nenhuma ação foi proposta.")
    elif not tipos & {"acao_aprovada", "acao_rejeitada"}:
        linhas.append("Nenhuma pessoa aprovou nem rejeitou proposta.")
    if "atacante_apontado" not in tipos:
        linhas.append("A triagem não apontou atacante.")
    if "acao_executada" not in tipos:
        linhas.append("Nenhuma ação foi aplicada.")
    elif "efeito_verificado" not in tipos:
        linhas.append("Nenhum efeito foi verificado.")
    if desfecho is not None:
        linhas.append(f"Desfecho: {DESFECHOS.get(desfecho, desfecho)}.")
    return "\n".join(linhas)


def escrever_sumario(incidente, *, log, perfil, onde, desfecho=None, **limites_do_laco):
    """Pede o sumário ao modelo da triagem e o grava no log. Devolve o texto, ou None se não veio resposta."""
    fatos = fatos_do_incidente(list(ler(log)), incidente, desfecho)
    gravador = GravadorDoAgente("triagem", log)
    mensagens = [
        {"role": "system", "content": SISTEMA_DO_SUMARIO},
        {"role": "user", "content": ABERTURA_DO_SUMARIO.format(incidente=incidente, fatos=fatos)},
    ]
    resultado = rodar(
        perfil.provedor, perfil.modelo, mensagens, [], _sem_tools,
        ao_chamar=chamadas_no_log(gravador, incidente, onde), **limites_do_laco,
    )
    # O texto em parágrafos do contrato não aceita caractere de controle além da quebra de linha.
    texto = "".join(letra for letra in (resultado.resposta or "") if letra == "\n" or letra.isprintable()).strip()
    if not resultado.terminou_bem or not texto:
        return None
    if len(texto) > TEXTO_LONGO:
        texto = texto[: TEXTO_LONGO - 1].rstrip() + "…"
    gravador.gravar(novo("sumario_emitido", {"agente": "triagem", "texto": texto}, incidente))
    return texto


def _sem_tools(nome, _argumentos):
    raise ValueError(f"o sumário não chama tools, e o modelo pediu {nome}")
