"""As skills dos agentes (`codigo/agente/skills/*/SKILL.md`) lidas como prompts de sistema."""

import os
import re

TITULO = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)


def _sem_cabecalho(texto):
    """Tira o cabeçalho YAML (`---` ... `---`) do começo do arquivo, se ele existir e fechar."""
    if not texto.startswith("---"):
        return texto
    fim = texto.find("\n---", 3)
    return texto[fim + 4 :] if fim >= 0 else texto


def ler_prompts(pasta):
    """Um item por subpasta com `SKILL.md`, em ordem de nome: `nome`, `titulo` e `texto`.

    `texto` é o arquivo sem o cabeçalho YAML; `titulo` é o primeiro título de nível 1, ou o nome
    da pasta quando não há título. Pasta inexistente devolve lista vazia.
    """
    if not os.path.isdir(pasta):
        return []
    prompts = []
    for nome in sorted(os.listdir(pasta)):
        caminho = os.path.join(pasta, nome, "SKILL.md")
        if not os.path.isfile(caminho):
            continue
        with open(caminho, encoding="utf-8") as arquivo:
            texto = _sem_cabecalho(arquivo.read()).strip()
        titulo = TITULO.search(texto)
        prompts.append({"nome": nome, "titulo": titulo.group(1) if titulo else nome, "texto": texto})
    return prompts
