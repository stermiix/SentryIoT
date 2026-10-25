"""Os pedidos que o orquestrador manda aos modelos, montados sem chamar ninguém.

O orquestrador dos agentes vai mandar estes pedidos ao provedor, no formato de `chat/completions`.
Enquanto ele não existe, a simulação da interface monta o primeiro pedido e o mostra: o pcap chega
até a porta do modelo da triagem, e a chamada fica de fora.

Arquitetura híbrida (decisões de 19/10 e 25/10/2026): o agente de decisão roda no modelo de
fronteira e coordena o incidente, e a triagem e a execução rodam no modelo local. O orquestrador não
é um quarto agente: é o código que encadeia os três. O que chega à fronteira é o resumo do incidente
montado pelo servidor, com rótulos neutros no lugar dos endereços (`obter_resumo`).
"""

from pathlib import Path

from codigo.api.prompts import ler_prompts
from codigo.mcp.tipos import TOOLS

PASTA_DE_SKILLS = Path(__file__).with_name("skills")
SKILL_DA_TRIAGEM = "triagem-do-alerta"
# O mesmo complemento e a mesma abertura do teste de fumaça de 14/10 com o gateway.
COMPLEMENTO_DO_SISTEMA = "Responda em português. Use as tools para ler o incidente antes de decidir."
ABERTURA_DA_TRIAGEM = (
    "Abriu o incidente {id} (evento incidente_aberto). Faça a triagem e devolva o veredito no formato da skill."
)


def tools_da_linha(agente):
    """As tools que o agente enxerga, no formato de `tools` da API compatível com OpenAI."""
    return [
        {
            "type": "function",
            "function": {"name": tool.nome, "description": tool.descricao, "parameters": tool.entrada.model_json_schema()},
        }
        for tool in TOOLS
        if agente in tool.agentes
    ]


def prompt_da_skill(nome, pasta=PASTA_DE_SKILLS):
    for skill in ler_prompts(str(pasta)):
        if skill["nome"] == nome:
            return skill["texto"]
    raise ValueError(f"skill {nome} não encontrada em {pasta}")


def pedido_da_triagem(incidente, modelo, parametros, pasta=PASTA_DE_SKILLS):
    """O primeiro pedido ao modelo da triagem para um incidente recém-aberto."""
    return {
        "model": modelo,
        "messages": [
            {"role": "system", "content": prompt_da_skill(SKILL_DA_TRIAGEM, pasta) + "\n\n" + COMPLEMENTO_DO_SISTEMA},
            {"role": "user", "content": ABERTURA_DA_TRIAGEM.format(id=incidente)},
        ],
        "tools": tools_da_linha("triagem"),
        "stream": False,
        **parametros,
    }
