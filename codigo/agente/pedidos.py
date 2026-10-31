"""O que o orquestrador usa para montar os pedidos aos modelos, sem chamar ninguém.

Arquitetura híbrida (decisões de 19/10 e 25/10/2026): o agente de decisão roda no modelo de
fronteira e coordena o incidente, e a triagem e a execução rodam no modelo local. O orquestrador não
é um quarto agente: é o código que encadeia os três. O que chega à fronteira é o resumo do incidente
montado pelo servidor, com rótulos neutros no lugar dos endereços (`obter_resumo`).
"""

from pathlib import Path

from codigo.api.prompts import ler_prompts

PASTA_DE_SKILLS = Path(__file__).with_name("skills")
# O mesmo complemento e a mesma abertura do teste de fumaça de 14/10 com o gateway.
COMPLEMENTO_DO_SISTEMA = "Responda em português. Use as tools para ler o incidente antes de decidir."
ABERTURA_DA_TRIAGEM = (
    "Abriu o incidente {id} (evento incidente_aberto). Faça a triagem e devolva o veredito no formato da skill."
)


def prompt_da_skill(nome, pasta=PASTA_DE_SKILLS):
    for skill in ler_prompts(str(pasta)):
        if skill["nome"] == nome:
            return skill["texto"]
    raise ValueError(f"skill {nome} não encontrada em {pasta}")
