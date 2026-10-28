# Contrato MCP, servidor e log de eventos

Esta pasta define a interface entre o lado do classificador e o lado dos agentes e entrega o
servidor MCP que responde nesse formato (`stub.py`). Com ele no ar, dá para chamar as dez
tools, percorrer um incidente do começo ao fim (ler, propor, aprovar, executar, desfazer) e
obter o log de eventos que a interface web lê. Ele atende os quatro incidentes de exemplo de
`cenarios.py`, que servem aos testes, ou, com `--cenarios`, os incidentes reais que o
reprodutor de tráfego monta a partir de um pcap. É esse o servidor da PoC, em modo de
reprodução (decisão de 2026-10-25): nada nele toca a rede, e o efeito das ações é simulado
(ver "O que é de mentira").

Todos os comandos são dados a partir da raiz do repositório, com o ambiente do
`requirements.txt` ativo.

## Arquivos

| Arquivo | Papel |
|---|---|
| `tipos.py` | Os tipos do contrato: o que cada tool recebe e devolve, o formato de cada linha do log e o filtro de endereços da linha de decisão |
| `contrato.json` | O mesmo contrato em JSON Schema, gerado de `tipos.py` |
| `acoes.py` | Catálogo de ações, política de risco, rótulos neutros, resumo do incidente, conferência do log e ambiente simulado, com desfazer |
| `politica.toml` | Os números da política de risco, os alvos em que cada ação é de risco baixo, os endereços protegidos e críticos e as redes locais, para ajustar sem mexer no código |
| `base.py` | Leitura da base de mitigações e a busca de `pesquisar_solucoes`. A base é o levantamento da equipe em `codigo/agente/recomendacoes/`, com a ação do catálogo e a fonte de cada medida |
| `eventos.py` | Gravação e leitura do log de eventos, e o gravador restrito que os agentes usam |
| `cenarios.py` | Os quatro incidentes de exemplo, com números ilustrativos |
| `stub.py` | O servidor MCP, em modo de reprodução |
| `aprovar.py` | O comando de terminal com que a pessoa vê a proposta inteira e aprova, rejeita ou promove, e marca um incidente como já resolvido |
| `roteiro.py` | Gera o log de exemplo em `exemplos/incidente_flood.jsonl` |

## Como subir o stub

    python -m codigo.mcp.stub --agente triagem
    python -m codigo.mcp.stub --agente decisao --log outro/caminho.jsonl
    python -m codigo.mcp.stub --agente todos
    python -m codigo.mcp.stub --agente triagem --log captura.jsonl --cenarios captura.cenarios.json

O transporte é stdio: quem inicia o processo é o cliente MCP. Na partida o stub grava no log a
abertura dos quatro incidentes de exemplo, se eles ainda não estiverem lá.

Com `--cenarios`, o stub atende os incidentes de um pcap no lugar dos de exemplo: o reprodutor de
tráfego (`python -m codigo.reprodutor`) grava o log e, ao lado dele, os cenários com as janelas
reais, e imprime o comando para subir o stub sobre eles. Se o log já tem um incidente com o mesmo
identificador e outro começo ou outra categoria, o stub recusa subir, em vez de servir as janelas
de outro incidente.

`--agente` é obrigatório. Com `triagem`, `decisao` ou `execucao`, o servidor só expõe as tools
da linha desse agente e registra o nome dele em cada chamada. O indicado é um processo por
agente, todos sobre o mesmo log. `--agente todos` expõe as dez tools em um processo só e deixa
o campo `agente` do log nulo. Serve para desenvolvimento, e só para isso: com todas as tools, um
mesmo cliente propõe e executa, e a separação entre quem lê conteúdo da rede e quem aplica
ações deixa de existir. Na API Python vale o mesmo: `Stub(registro)` sem agente é erro, e todas
as tools só com `Stub(registro, agente="todos")`.

O stub não guarda estado na memória. A cada chamada ele lê o log, confere a sequência dos
eventos, decide e grava. Apagar o log zera tudo. Vários processos podem trabalhar sobre o mesmo
arquivo onde existe `fcntl` (Linux e macOS), porque cada chamada trava o arquivo da leitura à
gravação. No Windows não há essa trava, e nada impede um segundo processo de abrir o mesmo log:
lá, use um processo só. Isso não é conferido (ver "Limites do stub").

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
`content`. O cliente deve usar um prazo por chamada (`asyncio.wait_for`), como `test_stdio.py`
faz: uma mensagem que o SDK descarta no nível do JSON-RPC fica sem resposta.

## Cenários

Os números são ilustrativos e os endereços são de faixas reservadas para documentação. Toda
janela tem 100 quadros, como no sistema (decisão de 2026-10-10), e as janelas de cada incidente
fecham com a taxa e a duração dele.

| Incidente | Cenário | Categoria | O que exercita | Efeito das ações |
|---|---|---|---|---|
| `inc-0001` | Flood de SYN, 37 origens | DDoS (o modelo diz `DDoS+DoS`) | A primeira ação não resolve, e o agente precisa procurar outra | persiste, depois cessou |
| `inc-0002` | Força bruta em SSH, 1 origem | BruteForce | O caminho curto, com ação de risco baixo | cessou |
| `inc-0003` | Varredura de portas, 1 origem | Recon | Efeito parcial | diminuiu, depois cessou |
| `inc-0004` | Falso positivo: câmera enviando vídeo | DoS (o modelo diz `DDoS+DoS`), confiança 0,58 | A triagem deve apontar a dúvida, sem ação de risco alto | cessou |

O efeito segue o roteiro do cenário: depende de quantas ações já foram aplicadas no incidente,
e não de qual ação foi. No `inc-0001`, a primeira ação aplicada sempre deixa o incidente como
está e a segunda sempre resolve.

## Tools

| Tool | Agentes | Devolve |
|---|---|---|
| `obter_incidente(id)` | triagem | O incidente, com os endereços |
| `obter_janelas(id, limite)` | triagem | Até 20 janelas, espaçadas ao longo do incidente, com as 39 features |
| `obter_resumo(id)` | decisão | O resumo montado pelo servidor, sem endereço, com os rótulos neutros |
| `consultar_mitigacoes(categoria)` | decisão | Até 10 mitigações recomendadas e o catálogo de ações |
| `pesquisar_solucoes(consulta)` | decisão | Até 3 trechos da base local, com o arquivo de origem |
| `propor_acao(id, acao, alvo, parametros, justificativa)` | decisão | A proposta, com o risco, os motivos quando o risco é alto e se exige aprovação |
| `verificar_efeito(id_execucao)` | execução | `cessou`, `diminuiu` ou `persiste` |
| `executar_acao(id_proposta)` | execução | A execução, se a proposta estiver liberada |
| `desfazer_acao(id_execucao)` | execução | A execução, agora desfeita |
| `consultar_estado()` | execução | As medidas ativas no ambiente simulado |

### A linha de decisão não recebe endereço

O agente de decisão é o único que pode rodar num modelo de nuvem (arquitetura híbrida, decisão
de 2026-10-10). Nenhum endereço da rede chega a ele, e quem garante isso é o servidor, não o
prompt:

- ele não tem `obter_incidente` nem `obter_janelas`, que trazem endereços. Lê o incidente por
  `obter_resumo`, montado por código: categorias, confiança, contagens, features com a referência
  do tráfego benigno, estado, último efeito verificado, a marca de já resolvido e, no lugar de
  cada endereço, um rótulo neutro (`origem-1`, `destino-1`);
- o rótulo segue a ordem em que o endereço apareceu no incidente e não muda quando o incidente é
  atualizado e a lista é reordenada. O papel faz parte do rótulo: o endereço que aparece nas
  origens e nos destinos ganha um de cada;
- `propor_acao` aceita o rótulo como alvo (`origem-1`, `destino-1`, `admin@destino-1`). O servidor
  o troca pelo endereço, calcula o risco sobre o endereço real e grava os dois na proposta:
  `alvo`, com o endereço, e `alvo_com_rotulo`. Na resposta à linha de decisão, `alvo` volta com o
  rótulo. Da linha de decisão, alvo com endereço é recusado (`alvo_malformado`): o agente não
  conhece endereço, e o que vier com um foi copiado de texto de fora. A ação nova pode descrever
  o alvo em texto, sem endereço. O rótulo escrito de outro jeito (`DESTINO-1`, `destino-01`, "o
  destino-1") também é recusado, porque não seria trocado pelo endereço;
- o agente de execução, local, recebe o endereço real em `executar_acao`, e a tela de aprovação
  mostra o endereço de cada rótulo citado na proposta;
- `verificar_efeito` não está na linha de decisão: ele grava o efeito e encerra ou atualiza o
  incidente. O agente de decisão lê o último efeito em `obter_resumo`;
- toda resposta à linha de decisão, inclusive a mensagem de recusa, inteira e antes do corte,
  passa por um filtro que troca qualquer IPv4, IPv6 ou MAC que tenha sobrado em texto livre (num
  documento da base, numa ação promovida, no eco da consulta) por `[endereço]`. A recusa de um alvo
  escrito com rótulo repete o rótulo, e não o endereço. A busca é larga de propósito e não olha o que
  vem antes ou depois do endereço: um IPv4 com zero à esquerda, octal, fora da faixa, desarmado
  (`203.0.113[.]7`) ou com dígitos de largura total, um IPv6 de um grupo só (`fe80::`, `::1`),
  depois de `src:` ou colado a uma letra e o MAC sem zero à esquerda também viram o marcador. As
  buscas não retrocedem, e o custo é linear no tamanho do texto. A falha é fechada: se a resposta
  filtrada sai do contrato (um título que passa de 200 caracteres com o marcador, por exemplo),
  ela não é entregue, e nada é gravado.

Um teste (`test_seguranca.py`) percorre todas as tools da linha de decisão, em todos os
cenários, pelo servidor MCP, com um documento da base cheio de endereços e uma ação promovida com
endereço nos passos, e falha se algum endereço aparecer.

### Exemplos

Os exemplos abaixo são respostas reais do stub. Onde aparece `...`, a resposta foi encurtada.

**`obter_incidente`** (triagem)

```json
{"id": "inc-0001"}
```
```json
{"id": "inc-0001", "estado": "aberto", "categoria": "DDoS", "categoria_do_modelo": "DDoS+DoS",
 "confianca": 0.97, "inicio": "2026-10-20T14:03:11Z", "fim": "2026-10-20T14:03:41Z",
 "janelas": 10734, "origens_distintas": 37, "distribuido": true,
 "origens": [{"endereco": "203.0.113.7", "quadros": 61240}, ...],
 "destinos": [{"endereco": "192.168.137.20", "quadros": 1073352}],
 "features_principais": [{"nome": "Rate", "valor": 35778.4, "referencia_benigno": 96.2}, ...]}
```

`categoria_do_modelo` é o que o classificador disse, entre as 7 categorias do modelo do sistema,
que não separa DDoS de DoS e responde `DDoS+DoS` (`codigo/classificador/preparar.py`, alvo `7`).
`categoria` é o resultado depois da regra que separa DoS de DDoS pela quantidade de origens, entre
as 8 categorias, e é a que os agentes usam. O contrato recusa a combinação que a regra não
produziria, como `categoria` Recon com `categoria_do_modelo` `DDoS+DoS`. Os endereços de `origens`
e `destinos` são endereços IP validados, e o `nome` de cada feature é uma das 39 colunas do
extrator.

**`obter_janelas`** (triagem)

```json
{"id": "inc-0001", "limite": 2}
```
```json
{"incidente": "inc-0001", "total": 10734,
 "janelas": [{"indice": 0, "instante": "2026-10-20T14:03:11Z", "categoria_do_modelo": "DDoS+DoS",
              "confianca": 0.98, "origem": "198.51.100.4", "destino": "192.168.137.20",
              "features": {"Header_Length": 20.0, "Protocol Type": 6.0, "Time_To_Live": 58.3,
                           "Rate": 38593.0, "syn_flag_number": 1.0, "syn_count": 100.0, ...}},
             {"indice": 10733, ...}]}
```

Pedido acima de 20 devolve 20. Uma feature vem nula quando o extrator não produz número finito.

**`obter_resumo`** (decisão)

```json
{"id": "inc-0001"}
```
```json
{"id": "inc-0001", "estado": "aberto", "ja_resolvido": false, "categoria": "DDoS",
 "categoria_do_modelo": "DDoS+DoS", "confianca": 0.97, "duracao_s": 30.0, "janelas": 10734,
 "origens_distintas": 37, "distribuido": true,
 "origens": [{"rotulo": "origem-1", "quadros": 61240, "protegido": false}, ...],
 "destinos": [{"rotulo": "destino-1", "quadros": 1073352, "protegido": false}],
 "features_principais": [{"nome": "Rate", "valor": 35778.4, "referencia_benigno": 96.2}, ...],
 "ultimo_efeito": null}
```

`protegido` diz se o endereço é protegido ou crítico pela política, sem dizer qual é. Depois de
uma ação aplicada e verificada, `ultimo_efeito` traz o último efeito verificado no incidente, na
ordem do log:

```json
"ultimo_efeito": {"execucao": "exec-0001", "incidente": "inc-0001", "resultado": "persiste",
                  "observacao": "O tráfego do incidente continua no mesmo nível depois da ação."}
```

**`consultar_mitigacoes`** (decisão)

```json
{"categoria": "DDoS"}
```
```json
{"categoria": "DDoS",
 "mitigacoes": [{"origem": "ddos.md",
                 "titulo": "Aplicar filtros de tráfego por protocolo, porta e origens confirmadas, considerando o risco de bloquear tráfego legítimo.",
                 "texto": "Fonte: MITRE ATT&CK — T1498 (https://attack.mitre.org/techniques/T1498/)",
                 "acao": "bloquear_ip"}, ...],
 "acoes": [{"nome": "bloquear_ip", "descricao": "Bloqueia o tráfego vindo de um endereço de origem.",
            "alvo": "Rótulo de uma origem do incidente, como origem-1",
            "parametros": [{"nome": "duracao", "descricao": "Prazo da medida, em minutos (número inteiro, de 1 a 525.600)", "obrigatorio": false}],
            "regra": "Risco baixo quando o alvo é origem do incidente fora da rede local, a duracao é de até 15 minutos, o incidente tem menos de 5 medidas de risco baixo ativas e o sistema, somando os incidentes, menos de 10: o agente de execução aplica sem aprovação. Fora disso (sem duracao, duracao maior, alvo que não consta do incidente, alvo que é destino do incidente, isto é, o dispositivo atacado, endereço da rede local, endereço protegido pela política ou limite de medidas atingido), risco alto: só com aprovação humana.",
            "origem": "base", "passos": [], "efeito_esperado": null,
            "como_desfazer": "Retirar o bloqueio com desfazer_acao.", "fonte": null}, ...]}
```

Na linha de decisão, o `alvo` de cada ação de base é descrito com os rótulos. Para o processo
`--agente todos`, com o endereço (`"Endereço IP de origem, como 203.0.113.7"`). A resposta traz
até 10 mitigações, na ordem da base: as medidas do levantamento da categoria que têm uma ação do
catálogo, cada uma com a fonte no `texto`.

**`pesquisar_solucoes`** (decisão)

```json
{"consulta": "flood de SYN com muitas origens"}
```
```json
{"consulta": "flood de SYN com muitas origens", "fonte": "base_local",
 "trechos": [{"origem": "ddos.md",
              "titulo": "Habilitar SYN cookies quando houver evidência de SYN flood contra serviços TCP.",
              "texto": "Fonte: MITRE ATT&CK — T1499 (https://attack.mitre.org/techniques/T1499/)",
              "acao": null}, ...]}
```

Trecho com `acao` nula descreve uma medida que o catálogo não cobre. É candidata a ação nova.
A consulta tem até 2.000 caracteres.

**`propor_acao`**, com uma ação do catálogo, pela linha de decisão

```json
{"id": "inc-0001", "acao": "bloquear_ip", "alvo": "origem-1", "parametros": {"duracao": 10},
 "justificativa": "Origem com mais quadros no incidente."}
```
```json
{"id": "prop-0001", "incidente": "inc-0001", "acao": "bloquear_ip", "alvo": "origem-1",
 "alvo_com_rotulo": "origem-1", "parametros": {"duracao": 10},
 "justificativa": "Origem com mais quadros no incidente.", "nova": false, "risco": "baixo",
 "motivos_de_risco_alto": [], "exige_aprovacao": false, "estado": "liberada"}
```

No log, o evento `acao_proposta` traz os dois: `"alvo": "203.0.113.7", "alvo_com_rotulo":
"origem-1"`. Pelo processo `--agente todos`, o alvo também pode vir com o endereço, e então
`alvo_com_rotulo` é nulo.

O mesmo bloqueio de 10 minutos em um endereço que não consta do incidente, no gateway ou no
dispositivo atacado não é recusado: volta com `"risco": "alto"`, `"exige_aprovacao": true`,
`"estado": "aguardando_aprovacao"` e, em `motivos_de_risco_alto`, o porquê. Com
`"alvo": "destino-1"`, que é o destino do flood:

```json
{"id": "prop-0003", "incidente": "inc-0001", "acao": "bloquear_ip", "alvo": "destino-1",
 "alvo_com_rotulo": "destino-1", "parametros": {"duracao": 10}, "justificativa": "Destino do flood.",
 "nova": false, "risco": "alto",
 "motivos_de_risco_alto": [
   {"codigo": "alvo_e_destino_do_incidente",
    "descricao": "O alvo é destino do incidente, isto é, o dispositivo atacado, e esta ação só é de risco baixo sobre uma origem."},
   {"codigo": "alvo_na_rede_local",
    "descricao": "O alvo é um endereço da rede local, e bloqueá-lo equivale a isolar um dispositivo interno."}],
 "exige_aprovacao": true, "estado": "aguardando_aprovacao"}
```

Da linha de decisão, o alvo com endereço e o rótulo que não existe são recusados:

```
Na linha de decisão, o alvo de bloquear_ip é o rótulo neutro de um endereço do incidente, sozinho e escrito como vem em obter_resumo, como origem-1, destino-1 ou admin@destino-1, e não um endereço. Uma ação nova também pode descrever o alvo em texto, sem endereço e sem rótulo.
O rótulo 'origem-9' não existe no incidente inc-0001. Os rótulos dele são: origem-1, origem-2, origem-3, origem-4, origem-5, destino-1.
```

**`propor_acao`**, com uma ação nova

```json
{"id": "inc-0001", "acao": "ativar_syn_cookies", "alvo": "destino-1",
 "parametros": {"descricao": "Ativa SYN cookies no dispositivo atacado.",
                "passos": ["Ativar SYN cookies na pilha TCP do dispositivo atacado."],
                "efeito_esperado": "A fila de conexões pendentes deixa de esgotar.",
                "como_desfazer": "Desativar SYN cookies na pilha TCP do dispositivo atacado."},
 "justificativa": "O bloqueio de uma origem não resolveu."}
```
```json
{"id": "prop-0002", "incidente": "inc-0001", "acao": "ativar_syn_cookies", "alvo": "destino-1",
 "alvo_com_rotulo": "destino-1",
 "parametros": {"descricao": "...", "passos": ["..."], "efeito_esperado": "...", "como_desfazer": "...", "fonte": null},
 "justificativa": "O bloqueio de uma origem não resolveu.",
 "nova": true, "risco": "alto",
 "motivos_de_risco_alto": [{"codigo": "acao_nova", "descricao": "A ação é nova, fora do catálogo."}],
 "exige_aprovacao": true, "estado": "aguardando_aprovacao"}
```

**`executar_acao`** (execução)

```json
{"id_proposta": "prop-0001"}
```
```json
{"id": "exec-0001", "proposta": "prop-0001", "incidente": "inc-0001", "acao": "bloquear_ip",
 "alvo": "203.0.113.7", "parametros": {"duracao": 10}, "estado": "aplicada",
 "aplicada_em": "2026-10-11T14:44:46.254555Z", "desfeita_em": null}
```

A execução recebe o endereço real. Com a proposta `prop-0002` antes da aprovação, a resposta é
um erro de tool:

```
A proposta prop-0002 é de risco alto e aguarda aprovação humana. Ela só pode ser executada depois que uma pessoa aprovar.
```

**`verificar_efeito`** (execução)

```json
{"id_execucao": "exec-0001"}
```
```json
{"execucao": "exec-0001", "incidente": "inc-0001", "resultado": "persiste",
 "observacao": "O tráfego do incidente continua no mesmo nível depois da ação."}
```

**`consultar_estado`** (execução)

```json
{}
```
```json
{"bloqueios": [{"id": "exec-0001", "proposta": "prop-0001", "incidente": "inc-0001",
                "acao": "bloquear_ip", "alvo": "203.0.113.7", "parametros": {"duracao": 10},
                "estado": "aplicada", "aplicada_em": "2026-10-11T14:44:46.254555Z", "desfeita_em": null}],
 "limites": [], "isolamentos": [], "credenciais_revogadas": [], "outras_medidas": []}
```

**`desfazer_acao`** (execução)

```json
{"id_execucao": "exec-0001"}
```
```json
{"id": "exec-0001", "proposta": "prop-0001", "incidente": "inc-0001", "acao": "bloquear_ip",
 "alvo": "203.0.113.7", "parametros": {"duracao": 10}, "estado": "desfeita",
 "aplicada_em": "2026-10-11T14:44:46.254555Z", "desfeita_em": "2026-10-11T14:44:46.257084Z"}
```

## Ações e risco

O catálogo de base é o ponto de partida, não um limite. A tabela diz o alvo com o endereço, que é
o que fica gravado; da linha de decisão, o endereço é escrito com o rótulo neutro.

| Ação | Alvo | Parâmetros | Risco |
|---|---|---|---|
| `limitar_taxa` | Endereço IP | `duracao`, em minutos, obrigatória | Baixo com `duracao` de até 60, sobre origem ou destino do incidente, se as condições abaixo valerem. Senão, alto |
| `bloquear_ip` | Endereço IP de origem | `duracao`, em minutos, opcional | Baixo com `duracao` de até 15, sobre origem do incidente fora da rede local, se as condições abaixo valerem. Sem prazo, com prazo maior, sobre destino ou sobre endereço da rede local, alto |
| `isolar_dispositivo` | Endereço IP do dispositivo | nenhum | Sempre alto |
| `revogar_credencial` | `usuario@endereco` | nenhum | Sempre alto |
| Ação nova | Texto de uma linha | `descricao`, `passos`, `efeito_esperado`, `como_desfazer` e, se houver, `fonte` | Sempre alto |

O risco não depende só do nome da ação e da duração. Uma proposta é de risco baixo quando
todas estas condições valem:

1. a política marca a ação como de risco baixo e a `duracao` cabe no prazo máximo dela;
2. o alvo faz parte do incidente, na versão mais recente dele, no papel que a política aceita
   para a ação: em `limitar_taxa`, uma das `origens` ou um dos `destinos`; em `bloquear_ip`, só
   uma das `origens`;
3. na ação que só vale sobre origens (`bloquear_ip`), o alvo está fora das redes locais;
4. o incidente está aberto;
5. o alvo não é um endereço protegido (na política de exemplo, o gateway e a máquina de captura)
   nem crítico (o servidor MCP, o host do modelo local e o resolvedor DNS);
6. o incidente tem menos de 5 medidas de risco baixo ativas, e o sistema, somando todos os
   incidentes, menos de 10.

O destino do incidente é o dispositivo atacado. Limitar a taxa dele o mantém em serviço.
Bloqueá-lo o tira do ar, que é o que o ataque quer, e por isso o bloqueio de um destino é de
risco alto com qualquer prazo. O endereço que aparece nas origens e nos destinos conta como
destino: o dispositivo atacado responde ao ataque, e as respostas podem pô-lo entre as origens.

A origem de um flood UDP ou ICMP é forjável: o atacante põe nela o endereço que quiser. Por isso
bloquear uma origem da rede local é de risco alto (equivale a isolar um dispositivo interno), os
endereços críticos são tratados como protegidos (um bloqueio forjado contra o DNS ou contra o
host do modelo cortaria a rede ou os próprios agentes) e o teto de medidas de risco baixo vale
também para o sistema todo (cada incidente forjado teria o seu teto). Um endereço IPv6 que leva
dentro um IPv4 (compatível `::a.b.c.d`, SIIT `::ffff:0:a.b.c.d`, NAT64 `64:ff9b::/96`, NAT64 de uso
local `64:ff9b:1::/48` em qualquer das posições que o tamanho do prefixo permite, 6to4 `2002::/16`,
ISATAP `...:5efe:a.b.c.d` e Teredo, o cliente e o servidor) conta como esse IPv4 na conferência de
protegido, crítico e rede local. O IPv6 de ULA (`fc00::/7`) conta sempre como rede local; o prefixo
IPv6 global da rede, se houver, vai em `redes_locais`. Um prefixo NAT64 próprio da rede, fora de
`64:ff9b::/96` e de `64:ff9b:1::/48`, não é desembrulhado: o código não tem como saber onde está o
IPv4 dentro dele.

Quando alguma das condições falha, a proposta não é recusada: é registrada como de risco alto e
fica aguardando a pessoa. As exceções, que são recusadas, estão na tabela de recusas: endereço
especial como alvo, proposta para incidente encerrado ou marcado como já resolvido, e os tetos
de propostas pendentes e liberadas.

### Por que a proposta é de risco alto

A proposta traz em `motivos_de_risco_alto` a lista dos motivos, cada um com `codigo` e
`descricao`. A lista é vazia quando o risco é baixo, e só então. Ela aparece na resposta de
`propor_acao`, no evento `acao_proposta`, no resumo da chamada em `tool_chamada` (só os códigos)
e na tela do comando `aprovar`. Saem todos os motivos que valem, nesta ordem:

| Código | Frase | Quando |
|---|---|---|
| `acao_sempre_de_risco_alto` | A ação é sempre de risco alto, qualquer que seja o alvo ou o prazo. | `isolar_dispositivo`, `revogar_credencial`, ação promovida ao catálogo e ação de base que a política marca como de risco alto |
| `acao_nova` | A ação é nova, fora do catálogo. | Ação que não está no catálogo |
| `prazo_acima_do_limite` | A medida não tem prazo, ou o prazo pedido passa do máximo aceito para risco baixo. | `bloquear_ip` sem `duracao`, ou `duracao` acima do prazo máximo da ação |
| `alvo_fora_do_incidente` | O alvo não está entre as origens nem entre os destinos do incidente. | Ação de base sobre endereço que o incidente não traz |
| `alvo_e_destino_do_incidente` | O alvo é destino do incidente, isto é, o dispositivo atacado, e esta ação só é de risco baixo sobre uma origem. | `bloquear_ip` sobre um destino |
| `alvo_na_rede_local` | O alvo é um endereço da rede local, e bloqueá-lo equivale a isolar um dispositivo interno. | `bloquear_ip` sobre endereço de uma das `redes_locais` |
| `alvo_protegido` | O alvo é um endereço protegido pela política. | Ação de base sobre endereço protegido ou crítico, escrito direto ou dentro de um IPv6 |
| `orcamento_de_risco_baixo_esgotado` | O incidente já tem o máximo de medidas de risco baixo ativas. | Ação que seria de risco baixo, com 5 medidas de risco baixo ativas no incidente |
| `orcamento_global_de_risco_baixo_esgotado` | O sistema já tem o máximo de medidas de risco baixo ativas, somando todos os incidentes. | Ação que seria de risco baixo, com 10 medidas de risco baixo ativas no total |

Os códigos são estáveis: é por eles que o código dos agentes e a interface web decidem. A frase
é para a pessoa. As duas colunas estão em `contrato.json`, em `motivos_de_risco_alto`. Nas ações
que são sempre de risco alto, os motivos do alvo (`alvo_fora_do_incidente` e `alvo_protegido`)
também saem, para quem aprova o isolamento de um dispositivo saber que ele é o gateway ou que é
alheio ao incidente. O alvo de uma ação nova é texto livre e não é conferido.

Ação de risco baixo já nasce liberada, e o agente de execução a aplica sem aprovação. Na hora
de executar, o risco é calculado de novo, com a política e o incidente daquele momento: propor
várias medidas antes e executar depois não contorna os limites de 5 e de 10, e uma proposta de
risco baixo não executa depois que o incidente encerra.

Os números (60 e 15 minutos, 5 e 10 medidas, 10 propostas pendentes, 10 propostas liberadas), os
alvos em que cada ação é de risco baixo (`alvos_de_risco_baixo`, com `"origens"` ou
`"origens_e_destinos"`), os endereços protegidos e críticos e as redes locais ficam em
`politica.toml`. Três regras ficam no código e o arquivo não as baixa: `isolar_dispositivo`,
`revogar_credencial` e toda ação nova são sempre de risco alto. Um `politica.toml` que marque uma
das duas primeiras como de risco baixo é recusado na leitura.

### Fila de aprovação e propostas liberadas

Cada incidente tem no máximo 10 propostas aguardando aprovação ao mesmo tempo
(`propostas_aguardando_aprovacao_por_incidente`, em `politica.toml`). A proposta de risco alto
que seria a décima primeira é recusada, com o motivo `limite_de_propostas_pendentes` e uma
mensagem que diz quantas estão na fila:

```
O incidente inc-0001 já tem 10 propostas aguardando aprovação, que é o máximo aceito pela política, e esta proposta não foi registrada. Uma nova proposta de risco alto só entra depois que uma pessoa aprovar ou rejeitar alguma das pendentes.
```

A vaga abre quando a pessoa aprova ou rejeita uma das pendentes. O teto existe porque a fila é
lida por uma pessoa: sem ele, um agente enganado por conteúdo vindo da rede poderia registrar
propostas sem parar. Ele também fecha o caminho que o limite de medidas abria, em que cada
proposta além do limite virava de risco alto e ia para a fila.

A proposta de risco baixo não espera ninguém: nasce liberada e assim fica até ser executada.
Cada incidente tem no máximo 10 propostas liberadas e ainda não executadas
(`propostas_liberadas_por_incidente`), contando as aprovadas. A proposta de risco baixo que seria
a décima primeira é recusada, com o motivo `limite_de_propostas_liberadas`, até o agente de
execução aplicar alguma das liberadas.

O nome de uma ação nova usa letras minúsculas, números e sublinhado, como `ativar_syn_cookies`,
e tem até 60 caracteres. Uma ação nova aprovada e aplicada pode ser promovida ao catálogo pela
pessoa. Depois disso ela aparece em `consultar_mitigacoes`, continua de risco alto e é proposta
com `parametros` vazio: os passos e a forma de desfazer são os do catálogo, e a proposta que
trouxer qualquer parâmetro é recusada. A ação promovida volta a todas as sessões do agente de
decisão, em qualquer categoria, e por isso vai ao catálogo sem endereço: o `alvo` é genérico, e
o endereço que estiver na descrição, nos passos, no efeito, na forma de desfazer ou na fonte vira
`[endereço]`. A reconstrução do log confere que a ação promovida é exatamente essa, aplicando o
filtro de agora aos dois lados: uma promoção gravada por uma versão do filtro que deixou passar um
endereço continua válida.

No ambiente simulado, aplicar uma ação é gravar um evento. O prazo fica registrado, mas a
medida não expira sozinha: ela vale até ser desfeita.

### Limites de texto e de alvo

Quem chama as tools é um modelo de linguagem, e o que ele escreve chega a uma pessoa, na tela
de aprovação, ao log e, pelos parâmetros de uma ação nova, ao agente de execução. Por isso:

- Todo texto tem uma linha só. Caractere de controle (ESC, BEL, NUL, tabulação, quebra de
  linha), separador de linha do Unicode (U+0085, U+2028, U+2029) e inversão de direção do texto
  (U+202A a U+202E, U+2066 a U+2069) são recusados. Só o texto da recomendação e os trechos da
  base aceitam quebra de linha, para separar parágrafos.
- Além disso, o texto é uma lista do que é permitido: letras, marcas, números, pontuação,
  símbolos e espaços. Fica de fora o que a tela não mostra e o modelo lê: os caracteres de
  formatação (Cf), como as etiquetas U+E0000 a U+E007F, que escrevem texto invisível, e os de
  largura zero; os de uso privado (Co); os sem atribuição (Cn); os substitutos soltos (Cs); e os
  preenchimentos que o Unicode classifica como letra ou símbolo, mas que aparecem em branco
  (U+3164, U+2800, U+115F, U+1160 e U+FFA0). O alvo livre de uma ação nova segue a mesma regra.
- Texto curto tem até 200 caracteres: identificadores, `alvo`, `fonte`, títulos. Texto longo tem
  até 2.000: `justificativa`, `descricao`, cada passo, `efeito_esperado`, `como_desfazer`. Uma
  ação nova tem de 1 a 20 passos.
- `duracao` é um número inteiro de 1 a 525.600 minutos (um ano).
- O alvo de uma ação de base é um endereço IP sem zona, ou o rótulo neutro dele: `fe80::1%eth0` é
  recusado, porque o que vem depois de `%` é texto livre. IPv4 escrito como IPv6
  (`::ffff:192.168.137.1`) vira o IPv4. Em `revogar_credencial`, o usuário usa letras sem
  acento, números, ponto, hífen e sublinhado, tem até 64 caracteres e não começa por ponto nem
  por hífen.
- A mensagem de recusa mostra no máximo um trecho escapado do que veio. Os endereços desse trecho
  viram o marcador antes do corte final, para que nenhum pedaço de endereço sobre dele. O valor
  grande é cortado primeiro com folga (64 caracteres além do trecho, mais que qualquer endereço), e
  só essa janela passa pelo filtro, que troca também o pedaço de endereço que o corte deixar no fim
  dela: um argumento de megabytes não prende a trava do log. Quando o alvo veio com o rótulo, a
  recusa repete o que o agente escreveu, com o rótulo, e nunca o endereço em que o servidor o trocou.

Os limites de texto não estão no esquema de entrada de `propor_acao`, só na descrição dos
campos. É de propósito: quem confere é o servidor, e não o SDK, para que a tentativa fique
registrada como `recusa`.

**Para o servidor de verdade.** O alvo de uma ação vira argumento de um comando. O servidor
deve passá-lo como um item de uma lista de argumentos (`subprocess.run(["comando", alvo])`,
sem `shell=True`) e nunca montar uma linha de comando para um interpretador. A validação acima
reduz o que chega lá, mas não substitui esse cuidado.

## Recusas

Pedido recusado devolve erro de tool com a mensagem e grava um evento `recusa`. O servidor
continua no ar. O campo `motivo` do evento traz um destes códigos:

| Motivo | Quando |
|---|---|
| `identificador_desconhecido` | Incidente, proposta ou execução que não existe |
| `alvo_malformado` | Alvo fora do formato que a ação pede, com zona de IPv6, grande demais, com rótulo que não existe no incidente ou, na linha de decisão, com endereço |
| `alvo_nao_permitido` | Alvo que é endereço de loopback, não especificado, broadcast, multicast ou link-local |
| `incidente_encerrado` | Proposta para incidente que já foi encerrado |
| `incidente_ja_resolvido` | Proposta ou execução de proposta de incidente que a pessoa marcou como já resolvido, inclusive a proposta já aprovada |
| `limite_de_propostas_pendentes` | Proposta de risco alto para incidente que já tem 10 propostas aguardando aprovação |
| `limite_de_propostas_liberadas` | Proposta de risco baixo para incidente que já tem 10 propostas liberadas e não executadas |
| `acao_nova_incompleta` | Ação nova sem descrição, passos, efeito esperado ou forma de desfazer, ou com texto fora dos limites |
| `argumentos_invalidos` | Parâmetro de ação inválido, justificativa vazia ou fora dos limites, nome de ação nova inválido, parâmetro em ação promovida, consulta grande demais |
| `proposta_nao_liberada` | Executar proposta que aguarda aprovação ou foi rejeitada, ou proposta de risco baixo que pelas regras de agora é de risco alto |
| `proposta_ja_executada` | Executar a mesma proposta outra vez |
| `acao_nao_aplicada` | Desfazer o que não está aplicado, ou verificar o efeito de ação desfeita |
| `tool_fora_da_linha` | Tool que não é da linha do agente |

O SDK confere os argumentos contra o esquema da tool antes de chamar o stub, em modo
permissivo: ele converte o que consegue e descarta o que não conhece. `"5"`, `5.0` e `true`
viram o inteiro pedido, e um argumento a mais, que o esquema não declara, é ignorado em
silêncio. Só o que não tem conversão é barrado pelo SDK: argumento faltando, `5.5` onde se
espera inteiro, `null`, categoria que não existe. Nesses casos o cliente recebe o erro do SDK, e
nenhum evento é gravado.

Com o log inconsistente (linha fora do contrato, ou evento que não cabe na sequência), nenhuma
tool é atendida. O cliente recebe um erro de tool que diz isso, sem trecho do log, e o arquivo e
a linha aparecem na saída de erro do servidor.

## Como aprovar pelo terminal

A aprovação e a rejeição não são tools: nenhum agente consegue aprovar a própria proposta.
Elas entram por este comando, em outro terminal, com o stub no ar ou não.

    python -m codigo.mcp.aprovar                      # lista o que aguarda aprovação
    python -m codigo.mcp.aprovar prop-0002            # mostra a proposta e pede confirmação para aprovar
    python -m codigo.mcp.aprovar prop-0002 --rejeitar --motivo "o dispositivo não pode parar"
    python -m codigo.mcp.aprovar prop-0002 --promover # leva a ação nova, já aplicada, para o catálogo
    python -m codigo.mcp.aprovar --resolvido inc-0002 --motivo "bloqueei a origem no roteador"

Aprovar e promover mostram a proposta inteira, com os motivos do risco alto e todos os
parâmetros, e só gravam depois que a pessoa digita `sim`. Quando o agente de decisão escreveu
com os rótulos neutros, a tela mostra o endereço de cada um:

```
prop-0002  incidente inc-0001  risco alto
  motivos do risco alto:
    - acao_nova: A ação é nova, fora do catálogo.
  ação: ativar_syn_cookies (nova, fora do catálogo)
  alvo: 192.168.137.20 (destino-1, como o agente de decisão escreveu)
  justificativa: O bloqueio de origem-1 não resolveu.
  descrição: Ativa SYN cookies no dispositivo atacado.
  passos:
    1. Ativar SYN cookies na pilha TCP do dispositivo atacado.
  efeito esperado: A fila de conexões pendentes deixa de esgotar.
  como desfazer: Desativar SYN cookies na pilha TCP do dispositivo atacado.
  rótulos citados: destino-1 = 192.168.137.20, origem-1 = 203.0.113.7
Aprovar prop-0002? Com a aprovação, o agente de execução pode aplicar a ação acima. Digite sim para confirmar:
```

Qualquer outra resposta encerra o comando sem gravar nada. Sem terminal interativo, o comando
não aprova nem promove, a não ser com `--sim`, que dispensa a pergunta e existe para testes e
roteiros. Rejeitar não libera nada e por isso não pede confirmação. Se a proposta mudar entre a
tela e a gravação, nada é gravado. A decisão grava o canal (`terminal`) e o usuário do sistema
que rodou o comando, lido da conta do processo.

Em uma ação de base que aceita prazo, a linha `duracao` aparece sempre, com a unidade:
`duracao: 600 minutos` ou `duracao: sem prazo, até a medida ser desfeita`.

**Já resolvido.** A pessoa que opera a rede é avisada quando o incidente abre e pode agir antes
dos agentes (decisão de 2026-10-10). `--resolvido` marca o incidente como já resolvido, com o
motivo opcional, e grava o evento `incidente_marcado_resolvido`, com o canal e o usuário do
sistema. Mais adiante, o botão "Já resolvido" da interface grava o mesmo evento, com o canal
`interface`. Daí em diante o servidor recusa qualquer proposta do incidente e a execução de
qualquer proposta dele, inclusive a já aprovada (`incidente_ja_resolvido`), e o comando recusa
aprovar a proposta pendente do incidente, que só pode ser rejeitada; o que já estava aplicado pode
ser desfeito. O agente de decisão vê a marca em `ja_resolvido`, no resumo, e só
explica o incidente. A marca vale uma vez, em incidente aberto, e não é desfeita. Como rejeitar,
ela não libera nada e não pede confirmação. A lista de pendentes avisa quando a proposta é de
incidente marcado e, para ela, só sugere a rejeição.

O log é entrada, e o comando não confia nele para escrever na tela: tudo o que não é imprimível
sai escapado. Uma sequência de terminal gravada em um parâmetro aparece como `\x1b[3A`, em vez
de mover o cursor e trocar o que a pessoa lê.

Se o stub foi iniciado com `--log`, passe o mesmo `--log` ao comando.

## Log de eventos

O log fica em `dados/eventos/eventos.jsonl`, fora do git, ou no caminho dado em `--log`. É um
arquivo de texto com um objeto JSON por linha, só de acréscimo. Os campos comuns são `id`,
`instante`, `tipo`, `incidente` (nulo quando não há) e `dados`, cujo formato depende do tipo.

O log traz endereços, alvos e contas da rede. O arquivo é criado só com leitura e escrita para o
dono (0600), e a pasta que o log cria, com 0700. O caminho do log que é link simbólico, mesmo
pendente, é recusado na gravação e na leitura.

| Tipo | Quem grava | `dados` |
|---|---|---|
| `janelas_classificadas` | classificador (no stub, a partida) | Janelas do lote e contagem por categoria do modelo |
| `incidente_aberto`, `incidente_atualizado`, `incidente_encerrado` | política de acionamento (no stub, a partida e `verificar_efeito`) | O incidente inteiro |
| `incidente_marcado_resolvido` | comando `aprovar --resolvido` (mais adiante, a interface) | Incidente, canal, usuário e motivo |
| `llm_chamada` | agentes, pelo `GravadorDoAgente` | Agente, modelo, tokens de entrada e de saída, duração |
| `tool_chamada` | servidor | Agente, nome da tool, argumentos, resultado resumido, duração |
| `recomendacao_emitida` | agente de decisão, pelo `GravadorDoAgente` | Agente, texto e propostas ligadas |
| `acao_proposta` | servidor | A proposta, com o alvo e o alvo com rótulo, e os motivos quando o risco é alto |
| `acao_aprovada`, `acao_rejeitada` | comando `aprovar` | Proposta, canal, usuário e motivo |
| `acao_executada`, `acao_desfeita` | servidor | A execução |
| `efeito_verificado` | servidor | Execução, incidente, resultado e observação |
| `catalogo_ampliado` | comando `aprovar --promover` | Proposta e a ação promovida |
| `recusa` | servidor | Agente, tool, argumentos, motivo e mensagem |

Uma chamada de tool atendida grava `tool_chamada` e, em seguida, os eventos que ela produziu.
Uma chamada recusada grava só `recusa`. As tools sem identificador (`consultar_mitigacoes`,
`pesquisar_solucoes` e `consultar_estado`) ficam registradas no incidente da chamada anterior
do mesmo processo.

Os argumentos vão para o log como vieram quando cabem no contrato. O corte é feito em duas
etapas. Item a item: texto maior que 2.000 caracteres, lista ou objeto com mais de 20 itens,
estrutura com mais de 4 níveis e número que o leitor do log não aceitaria são gravados cortados,
com a marca `[cortado: ...]`. Depois, no total: os argumentos de uma chamada ocupam até 8 KB de
JSON; os que não cabem, na ordem em que vieram, viram `[cortado: N bytes]`. A proposta aceita fica
inteira no evento `acao_proposta`.

Cada evento ocupa uma linha, e cada linha é lida de volta antes de ser gravada: o que o leitor
não aceitaria não entra no arquivo. Os separadores de linha do Unicode vão escapados, para que
quem divide o arquivo com `splitlines()` veja as mesmas linhas.

Duas linhas de um log real, de um stub iniciado com `--agente todos`:

```json
{"id":"ev-000009","instante":"2026-10-05T00:09:16.236769Z","tipo":"tool_chamada","incidente":"inc-0001","dados":{"agente":null,"nome":"obter_incidente","argumentos":{"id":"inc-0001"},"resultado":{"estado":"aberto","categoria":"DDoS","confianca":0.97,"janelas":10734},"duracao_ms":0.476}}
{"id":"ev-000010","instante":"2026-10-05T00:09:16.277663Z","tipo":"tool_chamada","incidente":"inc-0001","dados":{"agente":null,"nome":"obter_janelas","argumentos":{"id":"inc-0001","limite":2},"resultado":{"janelas":2,"total":10734},"duracao_ms":0.605}}
```

O código dos agentes grava `llm_chamada` e `recomendacao_emitida` pelo `GravadorDoAgente`, e
nada mais:

```python
from codigo.mcp.eventos import GravadorDoAgente, ler, novo

gravador = GravadorDoAgente("triagem")  # ou GravadorDoAgente("triagem", "outro/caminho.jsonl")
gravador.gravar(novo("llm_chamada", {
    "agente": "triagem", "modelo": "nome-do-modelo", "tokens_entrada": 1240, "tokens_saida": 96,
    "duracao_ms": 2100.0,
}, incidente="inc-0001"))

eventos = ler("dados/eventos/eventos.jsonl")  # cada linha conferida contra o contrato
```

O gravador recusa qualquer outro tipo de evento, recusa evento em nome de outro agente, recusa
evento de incidente que não existe no log e recusa recomendação que cite proposta que não existe
ou que é de outro incidente. `Registro`, que aceita todos os eventos, é do servidor e do comando
de aprovação: o código dos agentes não o usa.

A leitura do log confere a sequência de cada linha:

- o identificador do evento é a posição dele no arquivo (`ev-000001`, `ev-000002`...): uma linha
  apagada no meio, repetida ou fora de ordem deixa o log inválido;
- o instante não volta no tempo. O gravador não deixa isso acontecer quando o relógio da máquina
  é acertado para trás: o evento novo fica, no mínimo, com o instante do último;
- o `incidente` do evento é o mesmo que vem dentro de `dados`, nos tipos que o trazem.

O estado das propostas, das aprovações e das medidas ativas sai do log:
`codigo.mcp.acoes.reconstruir(eventos)`. A reconstrução confere cada evento no ponto em que ele
aparece:

- identificador de proposta e de execução é único;
- aprovação e rejeição só valem para proposta que aguarda aprovação, e ficam no incidente dela; a
  aprovação não vale depois da marca de já resolvido;
- execução só vale para proposta liberada ou aprovada, de incidente não marcado como já
  resolvido, e precisa ser a aplicação do que a proposta descreve;
- nenhum evento cita proposta, execução ou incidente que não existe, e a recomendação só cita
  proposta do próprio incidente;
- a proposta nasce no estado que o risco dela pede, nunca como de risco baixo se a ação é das
  que são sempre de risco alto, e nunca em incidente marcado como já resolvido;
- a proposta de risco alto traz ao menos um motivo, a de risco baixo não traz nenhum, e cada
  motivo vem uma vez só, com a frase que o contrato dá ao código;
- o rótulo gravado na proposta dá, no incidente, o alvo gravado;
- o efeito verificado é do incidente da execução, e a ação promovida é exatamente a que sai da
  proposta aprovada e aplicada;
- o incidente abre uma vez e não volta a aberto depois de encerrado, e a marca de já resolvido
  vale uma vez, em incidente aberto, como no comando.

A violação levanta `LogInvalido` (um `ValueError`), com o arquivo e a linha, como em
`eventos.jsonl, linha 14: acao_aprovada fora de lugar: a proposta prop-0001 não aguarda
aprovação: está executada`. Além disso, `executar_acao` não confia no campo `estado` lido: só
executa proposta que exige aprovação se o evento de aprovação estiver no log, e calcula de novo
o risco da proposta de risco baixo.

`exemplos/incidente_flood.jsonl` é um log completo e versionado, com os 16 tipos de evento: o
flood do começo ao fim e um incidente de força bruta que a pessoa resolve antes dos agentes. Os
valores são de roteiro. Os testes da interface web o leem, mas a interface não o carrega.

## Arquivos gerados

    python -m codigo.mcp.tipos                    # gera contrato.json a partir de tipos.py
    python -m codigo.mcp.roteiro --sobrescrever   # gera exemplos/incidente_flood.jsonl

Os dois têm teste: se `tipos.py`, os cenários ou o roteiro mudarem e o arquivo não for gerado
de novo, o `pytest` falha. O roteiro não grava por cima de um arquivo que já existe sem
`--sobrescrever`, nem no caminho padrão, nem no de `--saida`. Os testes da interface leem o log
de exemplo direto daqui: depois de gerá-lo de novo, rode também o `npm test` em `frontend/`.

## Versão do contrato

A versão fica em `contrato.json`, no campo `versao`, e sai de `VERSAO`, em `tipos.py`. A atual é
a 0.3.0. O que mudou em relação à 0.2.0, para quem já usava o stub:

- **Categoria do modelo.** `categoria_do_modelo`, no incidente e nas janelas, e `por_categoria`,
  em `janelas_classificadas`, usam as 7 categorias do modelo do sistema, com `DDoS+DoS` junto.
  `categoria` e `consultar_mitigacoes` continuam com as 8. O incidente com uma combinação que a
  regra das origens não produziria é recusado.
- **Arquitetura híbrida.** Tool nova, `obter_resumo`, na linha de decisão. `obter_incidente` fica
  só com a triagem, e `verificar_efeito`, só com a execução. `Proposta` ganhou o campo obrigatório
  `alvo_com_rotulo`. `propor_acao` aceita o rótulo neutro como alvo, e, na linha de decisão,
  recusa alvo com endereço. Toda resposta à linha de decisão passa pelo filtro de endereços. A
  ação promovida vai ao catálogo com alvo genérico e sem endereço nos textos.
- **Já resolvido.** Evento novo, `incidente_marcado_resolvido`, e motivo de recusa novo,
  `incidente_ja_resolvido`. O comando `aprovar` ganhou `--resolvido`.
- **Política.** Motivos novos de risco alto: `alvo_na_rede_local` e
  `orcamento_global_de_risco_baixo_esgotado`. `politica.toml` ganhou `enderecos_criticos`, em
  `[rede]`, e `medidas_de_risco_baixo_no_total` e `propostas_liberadas_por_incidente`, em
  `[limites]`; um arquivo de política sem essas chaves é recusado na leitura. Motivo de recusa
  novo: `limite_de_propostas_liberadas`. IPv6 que leva dentro um IPv4 protegido é protegido.
- **Quem decidiu.** `acao_aprovada` e `acao_rejeitada` trazem o campo obrigatório `usuario`.
- **Texto.** Os textos recusam caracteres de formatação, de uso privado, sem atribuição,
  substitutos soltos e os preenchimentos invisíveis.
- **Tetos.** `consultar_mitigacoes` devolve até 10 trechos e `pesquisar_solucoes`, até 3, agora
  também no esquema. Os argumentos de uma chamada ocupam até 8 KB no log.
- **Log.** O identificador do evento é a posição dele no arquivo, o instante não volta e o
  incidente do evento é o dos dados. O log nasce com modo 0600 e não segue link simbólico.
- **API Python.** `Stub` exige o agente; todas as tools só com `agente="todos"`.
- Um log gravado com a 0.2.0 não é lido pela 0.3.0. Apague o log e suba o stub de novo.

## Limites do stub

O que este desenho garante por código está nas seções acima. O que ele não garante está aqui,
para que o servidor de verdade não herde o limite sem saber.

**Quem consegue escrever no arquivo de log consegue aprovar.** A aprovação é uma linha
`acao_aprovada` no log. A conferência da sequência recusa a linha malformada, a repetida, a que
está fora de posição e a que cita proposta que não existe, mas uma linha bem formada,
acrescentada ao fim do arquivo com um `echo`, aprova a proposta. O mesmo vale para apagar as
últimas linhas do arquivo: a conferência pega a linha apagada no meio, e não a apagada no fim. O
`GravadorDoAgente` impede que o código dos agentes faça isso por engano, e só isso: ele é uma
restrição de interface, e o processo de um agente que tenha acesso de escrita ao arquivo pode
abri-lo diretamente. No stub, o servidor, o comando de aprovação e os agentes escrevem no mesmo
arquivo, com o mesmo usuário. O servidor de verdade precisa de um canal de decisão que o
processo do agente não escreve. Há três caminhos: gravar as decisões em um arquivo de outro
dono, que o agente só lê; assinar cada decisão com uma chave que só o canal da pessoa tem, e
conferir a assinatura ao reconstruir o estado; ou fazer do servidor o único escritor do log, com
os agentes e a interface falando só com ele. O mesmo vale para `--sim` e para `--agente todos`:
são opções da linha de comando, e quem pode rodar comandos na máquina pode usá-las.
`test_seguranca.py` registra esse limite como `xfail` estrito.

O que mais fica de fora deste trabalho:

- **Desfazer o que a pessoa aprovou.** O agente de execução desfaz, sem aprovação, uma medida de
  risco alto que uma pessoa aprovou, como o isolamento de um dispositivo comprometido. A pessoa
  também não consegue retirar uma aprovação antes da execução, nem vetar uma proposta de risco
  baixo. `test_seguranca.py` registra a primeira parte como `xfail` estrito.
- **Validade de uma aprovação no tempo.** Uma proposta aprovada pode ser executada a qualquer
  momento depois, inclusive com o incidente já encerrado. A aprovação não vence.
- **Releitura do log.** Cada chamada lê e confere o log inteiro, dentro da trava. O custo cresce
  com o arquivo: com dezenas de milhares de eventos, passa de meio segundo por chamada, e os
  processos dos agentes, o `aprovar` e a interface ficam em fila na trava. O servidor de verdade
  precisa guardar o estado e reler só o que entrou depois.
- **Leitura sem trava.** `ler`, usada pela listagem do `aprovar`, não toma a trava. Durante uma
  gravação grande, ela poderia ver uma linha pela metade e acusar log inválido. Não foi
  reproduzido.
- **Trava de arquivo no Windows.** A gravação usa `fcntl.flock`, que não existe no Windows. Lá
  não há trava, nada impede um segundo processo, e dois processos sobre o mesmo log podem repetir
  identificadores, o que deixa o log inválido.
- **Mensagem que o SDK descarta.** Uma mensagem que falha no nível do JSON-RPC (aninhamento de
  milhares de níveis, inteiro de milhares de dígitos) é descartada pelo SDK sem resposta. O
  servidor segue no ar, mas o cliente que espera a resposta fica parado: use prazo por chamada.
- **Expiração do prazo.** A `duracao` fica registrada, mas a medida não expira sozinha no
  ambiente simulado. Por isso uma medida de risco baixo conta para os limites de 5 e de 10 até ser
  desfeita, e uma proposta liberada que deixou de ser de risco baixo fica liberada, ocupando vaga
  no teto de liberadas, até a pessoa rejeitá-la, o que hoje não é possível.
- **Motivos e tetos na leitura do log.** A reconstrução confere que a proposta de risco alto traz
  motivo e que a frase é a do contrato, mas não refaz a conta do risco: os motivos gravados são
  os do momento da proposta, com a política e o incidente de então. Os tetos de propostas
  pendentes e liberadas valem na hora de propor, e a leitura do log não os confere.
- **O filtro de endereços é uma rede de proteção, não a garantia.** A garantia é a linha de
  decisão não ter tool que devolva endereço. O filtro pega IPv4 em quatro grupos de um a quatro
  dígitos separados por ponto, inclusive o IPv4 "desarmado" (`203.0.113[.]7`, `203(.)0(.)113(.)7`);
  IPv6 com `::` e ao menos um dígito (inclusive `fe80::` e `::1`), com seis ou mais dois-pontos ou
  que `ipaddress` reconhece, mesmo colado a letra ou depois de `nome:` (a letra hexadecimal colada
  vai junto para o marcador); e MAC de seis grupos de um ou dois dígitos com dois-pontos ou hífen,
  ou de três grupos de quatro com pontos. A busca corre sobre uma cópia do texto normalizada pela
  NFKC, só nos caracteres que viram dígito ou pontuação de endereço: os dígitos de largura total
  (`２０３．０．１１３．７`) são pegos, e o resto do texto sai como veio. Não pega endereço escrito
  como inteiro ou em hexadecimal (`0xc0a88914`), IPv4 com hífens (`ip-192-168-137-20`), IPv6
  desarmado com colchetes nos dois-pontos, MAC sem separador, nome de host nem endereço por extenso
  em palavras. Como a busca é larga, troca também o que só parece endereço: uma versão em quatro
  grupos (`1.2.3.4`), uma sequência de seis números separados por hífen ou o `d::` de `std::vector`.
- **O texto da triagem e o orquestrador.** O veredito da triagem é texto livre escrito por um
  modelo local, e quem o entrega ao agente de decisão é o orquestrador, ainda não escrito. Ele
  precisa passar esse texto pelo mesmo filtro (`tipos.mascarar_enderecos`) antes de mandá-lo à
  nuvem. Também não há teto de incidentes enviados ao modelo da nuvem: origens forjadas abrem
  incidentes, e cada um custa chamadas.
- **Rótulos em texto livre.** O agente de decisão pode citar rótulos nos passos de uma ação nova
  ("Ativar SYN cookies em destino-1"). O servidor só troca o rótulo que é o alvo inteiro; nos
  passos, quem resolve é a pessoa, que vê o endereço de cada rótulo na tela de aprovação, também
  quando ele vem em outra caixa ou com zero à esquerda, e o agente de execução, que recebe o alvo
  com o endereço.
- **Dependências transitivas.** O `requirements.txt` fixa as dependências diretas. As que elas
  trazem não estão fixadas nem conferidas por hash.
- **Histórico do que já foi tentado.** O resumo traz o último efeito verificado, mas não há tool
  que devolva as propostas e os efeitos anteriores do incidente. Hoje quem monta esse histórico é
  o código do agente, a partir do log.
- **Marca de origem contra injeção de prompt.** As respostas das tools não dizem, campo a
  campo, o que é dado do sistema e o que é texto vindo de fora. O stub limita o tamanho e os
  caracteres desses textos e tira deles os endereços na linha de decisão, mas não impede que uma
  instrução escrita em linguagem natural chegue ao modelo. `test_seguranca.py` registra esse
  limite como `xfail` estrito. No servidor de verdade, estes campos carregam texto de fora e
  devem ser marcados como não confiáveis antes de entrar no prompt:
  - `Trecho.titulo` e `Trecho.texto`, em `consultar_mitigacoes` e `pesquisar_solucoes`: vêm
    dos documentos da base e, se a busca na internet for ligada, de páginas de terceiros;
  - `AcaoDoCatalogo.descricao`, `passos`, `efeito_esperado`, `como_desfazer` e `fonte` das ações
    promovidas: foram escritos por um agente de decisão em uma sessão anterior e voltam para
    todas as sessões seguintes, em qualquer categoria;
  - `Proposta.justificativa`, `Proposta.alvo` e `Proposta.parametros` de ação nova: texto do
    agente de decisão;
  - `Execucao.alvo` e `Execucao.parametros`, em `executar_acao`, `desfazer_acao` e
    `consultar_estado`: é por aqui que texto escrito pelo agente de decisão chega ao agente de
    execução, que em princípio não lê conteúdo de fora;
  - `Recusa.mensagem`, que repete um trecho do argumento recusado;
  - `Incidente.origens`, `Incidente.destinos`, `Janela.origem` e `Janela.destino`: vêm dos
    pacotes, e por isso são endereços IP validados, e não texto;
  - `Recomendacao.texto`, `Decisao.motivo` e `MarcaDeResolvido.motivo`, que a interface web vai
    mostrar.

## O que é de mentira

- Sem `--cenarios`, os incidentes, as janelas e os efeitos das ações vêm de `cenarios.py`. Os
  números são ilustrativos e não podem ser citados como resultado.
- Com `--cenarios`, os incidentes e as janelas são os do pcap reproduzido, classificados pelo
  modelo do sistema. O efeito das ações continua simulado: toda verificação dá `cessou` na
  primeira ação aplicada (`EFEITOS_DO_REPLAY`, em `codigo/reprodutor/reprodutor.py`), porque a
  ação não age sobre o tráfego já gravado.
- Nenhuma ação toca a rede. O ambiente é simulado, e aplicar ou desfazer é gravar um evento.
- A busca de `pesquisar_solucoes` é por palavras, só na base local. A busca na internet fica
  desligada por padrão, como decidido na especificação: neste trabalho não há código que a
  ligue, e `fonte` é sempre `base_local`.
