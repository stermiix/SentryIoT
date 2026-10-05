# Contrato MCP, stub do servidor e log de eventos

Esta pasta define a interface entre o lado do classificador e o lado dos agentes e entrega um
servidor MCP de mentira (stub) que já responde nesse formato. Com o stub no ar, dá para chamar
as nove tools, percorrer um incidente do começo ao fim (ler, propor, aprovar, executar,
desfazer) e obter o log de eventos que a interface web vai ler, sem classificador treinado e
sem rede.

Todos os comandos são dados a partir da raiz do repositório, com o ambiente do
`requirements.txt` ativo.

## Arquivos

| Arquivo | Papel |
|---|---|
| `tipos.py` | Os tipos do contrato: o que cada tool recebe e devolve e o formato de cada linha do log |
| `contrato.json` | O mesmo contrato em JSON Schema, gerado de `tipos.py` |
| `acoes.py` | Catálogo de ações, política de risco e ambiente simulado, com desfazer |
| `politica.toml` | Os limites da política de risco, para ajustar sem mexer no código |
| `base.py` | Leitura da base local de documentos e a busca de `pesquisar_solucoes` |
| `base_provisoria/` | Os documentos da base. **Conteúdo provisório do stub** (ver o `README.md` da pasta) |
| `eventos.py` | Gravação e leitura do log de eventos |
| `cenarios.py` | Os quatro incidentes de exemplo, com números ilustrativos |
| `stub.py` | O servidor MCP de mentira |
| `aprovar.py` | O comando de terminal com que a pessoa aprova, rejeita ou promove |
| `roteiro.py` | Gera o log de exemplo em `exemplos/incidente_flood.jsonl` |

## Como subir o stub

    python -m codigo.mcp.stub
    python -m codigo.mcp.stub --agente decisao
    python -m codigo.mcp.stub --log outro/caminho.jsonl

O transporte é stdio: quem inicia o processo é o cliente MCP. Na partida o stub grava no log a
abertura dos quatro incidentes, se eles ainda não estiverem lá.

Com `--agente triagem`, `--agente decisao` ou `--agente execucao`, o servidor só expõe as tools
da linha desse agente e registra o nome dele em cada chamada. O indicado é um processo por
agente, todos sobre o mesmo log. Sem `--agente`, o servidor expõe as nove tools e o campo
`agente` do log fica nulo.

O stub não guarda estado na memória. A cada chamada ele lê o log, decide e grava. Por isso
vários processos podem trabalhar sobre o mesmo arquivo, e apagar o log zera tudo.

## Como ligar um cliente MCP

Em um cliente que lê configuração em JSON:

```json
{
  "mcpServers": {
    "sentryiot-decisao": {
      "command": "/caminho/do/repositorio/.venv/bin/python",
      "args": ["-m", "codigo.mcp.stub", "--agente", "decisao"],
      "cwd": "/caminho/do/repositorio"
    }
  }
}
```

Se o cliente não aceitar `cwd`, use `"env": {"PYTHONPATH": "/caminho/do/repositorio"}`.

Em Python, com o SDK oficial (`mcp`, já no `requirements.txt`):

```python
import asyncio
import sys

from mcp import Client, StdioServerParameters


async def main():
    stub = StdioServerParameters(command=sys.executable, args=["-m", "codigo.mcp.stub", "--agente", "triagem"])
    async with Client(stub) as cliente:
        tools = await cliente.list_tools()
        print([tool.name for tool in tools.tools])
        resposta = await cliente.call_tool("obter_incidente", {"id": "inc-0001"})
        print(resposta.structured_content)


asyncio.run(main())
```

A resposta de cada tool vem em `structured_content`, no formato do contrato, e repetida como
texto JSON em `content`. Pedido recusado vem com `is_error` verdadeiro e a mensagem em
`content`.

## Cenários

Os números são ilustrativos e os endereços são de faixas reservadas para documentação.

| Incidente | Cenário | Categoria | O que exercita | Efeito das ações |
|---|---|---|---|---|
| `inc-0001` | Flood de SYN, 37 origens | DDoS (o modelo diz DoS) | A primeira ação não resolve, e o agente precisa procurar outra | persiste, depois cessou |
| `inc-0002` | Força bruta em SSH, 1 origem | BruteForce | O caminho curto, com ação de risco baixo | cessou |
| `inc-0003` | Varredura de portas, 1 origem | Recon | Efeito parcial | diminuiu, depois cessou |
| `inc-0004` | Falso positivo: câmera enviando vídeo | DoS, confiança 0,58 | A triagem deve apontar a dúvida, sem ação de risco alto | cessou |

O efeito segue o roteiro do cenário: depende de quantas ações já foram aplicadas no incidente,
e não de qual ação foi. No `inc-0001`, a primeira ação aplicada sempre deixa o incidente como
está e a segunda sempre resolve.

## Tools

| Tool | Agentes | Devolve |
|---|---|---|
| `obter_incidente(id)` | triagem, decisão | O resumo do incidente |
| `obter_janelas(id, limite)` | triagem | Até 20 janelas, espaçadas ao longo do incidente, com as 39 features |
| `consultar_mitigacoes(categoria)` | decisão | As mitigações recomendadas e o catálogo de ações |
| `pesquisar_solucoes(consulta)` | decisão | Até 3 trechos da base local, com o arquivo de origem |
| `propor_acao(id, acao, alvo, parametros, justificativa)` | decisão | A proposta, com o risco e se exige aprovação |
| `verificar_efeito(id_execucao)` | decisão, execução | `cessou`, `diminuiu` ou `persiste` |
| `executar_acao(id_proposta)` | execução | A execução, se a proposta estiver liberada |
| `desfazer_acao(id_execucao)` | execução | A execução, agora desfeita |
| `consultar_estado()` | execução | As medidas ativas no ambiente simulado |

Os exemplos abaixo são respostas reais do stub. Onde aparece `...`, a resposta foi encurtada.

**`obter_incidente`**

```json
{"id": "inc-0001"}
```
```json
{"id": "inc-0001", "estado": "aberto", "categoria": "DDoS", "categoria_do_modelo": "DoS",
 "confianca": 0.97, "inicio": "2026-10-20T14:03:11Z", "fim": "2026-10-20T14:03:41Z",
 "janelas": 10734, "origens_distintas": 37, "distribuido": true,
 "origens": [{"endereco": "203.0.113.7", "quadros": 61240}, ...],
 "destinos": [{"endereco": "192.168.137.20", "quadros": 1073352}],
 "features_principais": [{"nome": "Rate", "valor": 35778.4, "referencia_benigno": 96.2}, ...]}
```

`categoria_do_modelo` é o que o classificador disse. `categoria` é o resultado depois da regra
que separa DoS de DDoS pela quantidade de origens. Os agentes usam `categoria`.

**`obter_janelas`**

```json
{"id": "inc-0001", "limite": 2}
```
```json
{"incidente": "inc-0001", "total": 10734,
 "janelas": [{"indice": 0, "instante": "2026-10-20T14:03:11Z", "categoria_do_modelo": "DoS",
              "confianca": 0.98, "origem": "198.51.100.4", "destino": "192.168.137.20",
              "features": {"Header_Length": 20.0, "Protocol Type": 6.0, "Time_To_Live": 58.3,
                           "Rate": 38593.0, "syn_flag_number": 1.0, "syn_count": 100.0, ...}},
             {"indice": 10733, ...}]}
```

Pedido acima de 20 devolve 20. Uma feature vem nula quando o extrator não produz número finito.

**`consultar_mitigacoes`**

```json
{"categoria": "DDoS"}
```
```json
{"categoria": "DDoS",
 "mitigacoes": [{"origem": "flood.md", "titulo": "Bloquear a origem do tráfego",
                 "texto": "Quando o tráfego vem de uma origem só, ...", "acao": "bloquear_ip"}, ...],
 "acoes": [{"nome": "bloquear_ip", "descricao": "Bloqueia o tráfego vindo de um endereço de origem.",
            "alvo": "Endereço IP de origem, como 203.0.113.7",
            "parametros": [{"nome": "duracao", "descricao": "Prazo da medida, em minutos (número inteiro, a partir de 1)", "obrigatorio": false}],
            "regra": "Risco baixo com duracao de até 15 minutos: o agente de execução aplica sem aprovação. Sem duracao ou com duracao maior, risco alto: só com aprovação humana.",
            "origem": "base", "passos": [], "efeito_esperado": null,
            "como_desfazer": "Retirar o bloqueio com desfazer_acao.", "fonte": null}, ...]}
```

**`pesquisar_solucoes`**

```json
{"consulta": "flood de SYN com muitas origens"}
```
```json
{"consulta": "flood de SYN com muitas origens", "fonte": "base_local",
 "trechos": [{"origem": "flood.md", "titulo": "Ativar SYN cookies no dispositivo ou no gateway",
              "texto": "Em flood de pacotes SYN, a fila de conexões pendentes ...", "acao": null}, ...]}
```

Trecho com `acao` nula descreve uma medida que o catálogo não cobre. É candidata a ação nova.

**`propor_acao`**, com uma ação do catálogo

```json
{"id": "inc-0001", "acao": "bloquear_ip", "alvo": "203.0.113.7", "parametros": {"duracao": 10},
 "justificativa": "Origem com mais quadros no incidente."}
```
```json
{"id": "prop-0001", "incidente": "inc-0001", "acao": "bloquear_ip", "alvo": "203.0.113.7",
 "parametros": {"duracao": 10}, "justificativa": "Origem com mais quadros no incidente.",
 "nova": false, "risco": "baixo", "exige_aprovacao": false, "estado": "liberada"}
```

**`propor_acao`**, com uma ação nova

```json
{"id": "inc-0001", "acao": "ativar_syn_cookies", "alvo": "192.168.137.20",
 "parametros": {"descricao": "Ativa SYN cookies no dispositivo atacado.",
                "passos": ["Ativar SYN cookies na pilha TCP de 192.168.137.20."],
                "efeito_esperado": "A fila de conexões pendentes deixa de esgotar.",
                "como_desfazer": "Desativar SYN cookies na pilha TCP de 192.168.137.20."},
 "justificativa": "O bloqueio de uma origem não resolveu."}
```
```json
{"id": "prop-0002", "incidente": "inc-0001", "acao": "ativar_syn_cookies", "alvo": "192.168.137.20",
 "parametros": {"descricao": "...", "passos": ["..."], "efeito_esperado": "...", "como_desfazer": "...", "fonte": null},
 "justificativa": "O bloqueio de uma origem não resolveu.",
 "nova": true, "risco": "alto", "exige_aprovacao": true, "estado": "aguardando_aprovacao"}
```

**`executar_acao`**

```json
{"id_proposta": "prop-0001"}
```
```json
{"id": "exec-0001", "proposta": "prop-0001", "incidente": "inc-0001", "acao": "bloquear_ip",
 "alvo": "203.0.113.7", "parametros": {"duracao": 10}, "estado": "aplicada",
 "aplicada_em": "2026-10-05T00:09:16.346378Z", "desfeita_em": null}
```

Com a proposta `prop-0002` antes da aprovação, a resposta é um erro de tool:

```
A proposta prop-0002 é de risco alto e aguarda aprovação humana. Ela só pode ser executada depois que uma pessoa aprovar.
```

**`verificar_efeito`**

```json
{"id_execucao": "exec-0001"}
```
```json
{"execucao": "exec-0001", "incidente": "inc-0001", "resultado": "persiste",
 "observacao": "O tráfego do incidente continua no mesmo nível depois da ação."}
```

**`consultar_estado`**

```json
{}
```
```json
{"bloqueios": [{"id": "exec-0001", "proposta": "prop-0001", "incidente": "inc-0001",
                "acao": "bloquear_ip", "alvo": "203.0.113.7", "parametros": {"duracao": 10},
                "estado": "aplicada", "aplicada_em": "2026-10-05T00:09:16.346378Z", "desfeita_em": null}],
 "limites": [], "isolamentos": [], "credenciais_revogadas": [], "outras_medidas": []}
```

**`desfazer_acao`**

```json
{"id_execucao": "exec-0001"}
```
```json
{"id": "exec-0001", "proposta": "prop-0001", "incidente": "inc-0001", "acao": "bloquear_ip",
 "alvo": "203.0.113.7", "parametros": {"duracao": 10}, "estado": "desfeita",
 "aplicada_em": "2026-10-05T00:09:16.346378Z", "desfeita_em": "2026-10-05T00:09:16.394725Z"}
```

## Ações e risco

O catálogo de base é o ponto de partida, não um limite. Os limites da tabela ficam em
`politica.toml`.

| Ação | Alvo | Parâmetros | Risco |
|---|---|---|---|
| `limitar_taxa` | Endereço IP | `duracao`, em minutos, obrigatória | Baixo |
| `bloquear_ip` | Endereço IP de origem | `duracao`, em minutos, opcional | Baixo com `duracao` de até 15. Sem prazo ou com prazo maior, alto |
| `isolar_dispositivo` | Endereço IP do dispositivo | nenhum | Alto |
| `revogar_credencial` | `usuario@endereco` | nenhum | Alto |
| Ação nova | Texto de uma linha | `descricao`, `passos`, `efeito_esperado`, `como_desfazer` e, se houver, `fonte` | Sempre alto |

Ação de risco baixo já nasce liberada, e o agente de execução a aplica sem aprovação. Ação de
risco alto fica aguardando a pessoa. O nome de uma ação nova usa letras minúsculas, números e
sublinhado, como `ativar_syn_cookies`. Uma ação nova aprovada e aplicada pode ser promovida ao
catálogo pela pessoa. Depois disso ela aparece em `consultar_mitigacoes` e dispensa repetir os
passos na proposta, mas continua de risco alto.

No ambiente simulado, aplicar uma ação é gravar um evento. O prazo fica registrado, mas a
medida não expira sozinha: ela vale até ser desfeita.

## Recusas

Pedido recusado devolve erro de tool com a mensagem e grava um evento `recusa`. O servidor
continua no ar. O campo `motivo` do evento traz um destes códigos:

| Motivo | Quando |
|---|---|
| `identificador_desconhecido` | Incidente, proposta ou execução que não existe |
| `alvo_malformado` | Alvo fora do formato que a ação pede |
| `acao_nova_incompleta` | Ação nova sem descrição, passos, efeito esperado ou forma de desfazer |
| `argumentos_invalidos` | Parâmetro de ação inválido, justificativa vazia, nome de ação nova inválido |
| `proposta_nao_liberada` | Executar proposta que aguarda aprovação ou foi rejeitada |
| `proposta_ja_executada` | Executar a mesma proposta outra vez |
| `acao_nao_aplicada` | Desfazer o que não está aplicado, ou verificar o efeito de ação desfeita |
| `tool_fora_da_linha` | Tool que não é da linha do agente |

Argumento fora do esquema da tool (tipo errado, argumento faltando, categoria que não existe) é
barrado pelo SDK antes de chegar ao stub. O cliente recebe o erro, e nenhum evento é gravado.

## Como aprovar pelo terminal

A aprovação e a rejeição não são tools: nenhum agente consegue aprovar a própria proposta.
Elas entram por este comando, em outro terminal, com o stub no ar ou não.

    python -m codigo.mcp.aprovar                      # lista o que aguarda aprovação
    python -m codigo.mcp.aprovar prop-0002            # aprova
    python -m codigo.mcp.aprovar prop-0002 --rejeitar --motivo "o dispositivo não pode parar"
    python -m codigo.mcp.aprovar prop-0002 --promover # leva a ação nova, já aplicada, para o catálogo

A lista mostra tudo o que será feito:

```
1 proposta aguarda aprovação:

prop-0002  incidente inc-0001  risco alto
  ação: ativar_syn_cookies (nova, fora do catálogo)
  alvo: 192.168.137.20
  justificativa: O bloqueio de uma origem não resolveu.
  descrição: Ativa SYN cookies no dispositivo atacado.
  passos:
    1. Ativar SYN cookies na pilha TCP de 192.168.137.20.
  efeito esperado: A fila de conexões pendentes deixa de esgotar.
  como desfazer: Desativar SYN cookies na pilha TCP de 192.168.137.20.
  para aprovar:  python -m codigo.mcp.aprovar prop-0002
  para rejeitar: python -m codigo.mcp.aprovar prop-0002 --rejeitar
```

Se o stub foi iniciado com `--log`, passe o mesmo `--log` ao comando.

## Log de eventos

O log fica em `dados/eventos/eventos.jsonl`, fora do git, ou no caminho dado em `--log`. É um
arquivo de texto com um objeto JSON por linha, só de acréscimo. Os campos comuns são `id`,
`instante`, `tipo`, `incidente` (nulo quando não há) e `dados`, cujo formato depende do tipo.

| Tipo | Quem grava | `dados` |
|---|---|---|
| `janelas_classificadas` | classificador (no stub, a partida) | Janelas do lote e contagem por categoria |
| `incidente_aberto`, `incidente_atualizado`, `incidente_encerrado` | política de acionamento (no stub, a partida e `verificar_efeito`) | O incidente inteiro |
| `llm_chamada` | agentes | Agente, modelo, tokens de entrada e de saída, duração |
| `tool_chamada` | servidor | Agente, nome da tool, argumentos, resultado resumido, duração |
| `recomendacao_emitida` | agente de decisão | Agente, texto e propostas ligadas |
| `acao_proposta` | servidor | A proposta |
| `acao_aprovada`, `acao_rejeitada` | comando `aprovar` | Proposta, canal e motivo |
| `acao_executada`, `acao_desfeita` | servidor | A execução |
| `efeito_verificado` | servidor | Execução, incidente, resultado e observação |
| `catalogo_ampliado` | comando `aprovar --promover` | Proposta e a ação promovida |
| `recusa` | servidor | Agente, tool, argumentos, motivo e mensagem |

Uma chamada de tool atendida grava `tool_chamada` e, em seguida, os eventos que ela produziu.
Uma chamada recusada grava só `recusa`. As tools sem identificador (`consultar_mitigacoes`,
`pesquisar_solucoes` e `consultar_estado`) ficam registradas no incidente da chamada anterior
do mesmo processo.

Duas linhas de um log real:

```json
{"id":"ev-000009","instante":"2026-10-05T00:09:16.236769Z","tipo":"tool_chamada","incidente":"inc-0001","dados":{"agente":null,"nome":"obter_incidente","argumentos":{"id":"inc-0001"},"resultado":{"estado":"aberto","categoria":"DDoS","confianca":0.97,"janelas":10734},"duracao_ms":0.476}}
{"id":"ev-000010","instante":"2026-10-05T00:09:16.277663Z","tipo":"tool_chamada","incidente":"inc-0001","dados":{"agente":null,"nome":"obter_janelas","argumentos":{"id":"inc-0001","limite":2},"resultado":{"janelas":2,"total":10734},"duracao_ms":0.605}}
```

Os agentes gravam `llm_chamada` e `recomendacao_emitida` pelo mesmo módulo:

```python
from codigo.mcp.eventos import Registro, ler, novo

registro = Registro()  # ou Registro("outro/caminho.jsonl")
registro.gravar(novo("llm_chamada", {
    "agente": "triagem", "modelo": "nome-do-modelo", "tokens_entrada": 1240, "tokens_saida": 96,
    "duracao_ms": 2100.0,
}, incidente="inc-0001"))

eventos = ler("dados/eventos/eventos.jsonl")  # cada linha conferida contra o contrato
```

O estado das propostas, das aprovações e das medidas ativas sai do log:
`codigo.mcp.acoes.reconstruir(eventos)`.

`exemplos/incidente_flood.jsonl` é um log completo e versionado, com os 15 tipos de evento, para
o modo replay da interface web.

## Arquivos gerados

    python -m codigo.mcp.tipos      # gera contrato.json a partir de tipos.py
    python -m codigo.mcp.roteiro    # gera exemplos/incidente_flood.jsonl

Os dois têm teste: se `tipos.py`, os cenários ou o roteiro mudarem e o arquivo não for gerado
de novo, o `pytest` falha.

## O que é de mentira

- Os incidentes, as janelas e os efeitos das ações vêm de `cenarios.py`. Os números são
  ilustrativos e não podem ser citados como resultado.
- Os documentos de `base_provisoria/` são provisórios e serão substituídos pelo levantamento de
  mitigações da equipe.
- Nenhuma ação toca a rede. O ambiente é simulado, e aplicar ou desfazer é gravar um evento.
- A busca de `pesquisar_solucoes` é por palavras, só na base local. Busca na internet não existe
  neste trabalho.
