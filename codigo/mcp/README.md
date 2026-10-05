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
| `acoes.py` | Catálogo de ações, política de risco, conferência do log e ambiente simulado, com desfazer |
| `politica.toml` | Os números da política de risco, os alvos em que cada ação é de risco baixo e os endereços protegidos, para ajustar sem mexer no código |
| `base.py` | Leitura da base local de documentos e a busca de `pesquisar_solucoes` |
| `base_provisoria/` | Os documentos da base. **Conteúdo provisório do stub** (ver o `README.md` da pasta) |
| `eventos.py` | Gravação e leitura do log de eventos, e o gravador restrito que os agentes usam |
| `cenarios.py` | Os quatro incidentes de exemplo, com números ilustrativos |
| `stub.py` | O servidor MCP de mentira |
| `aprovar.py` | O comando de terminal com que a pessoa vê a proposta inteira e aprova, rejeita ou promove |
| `roteiro.py` | Gera o log de exemplo em `exemplos/incidente_flood.jsonl` |

## Como subir o stub

    python -m codigo.mcp.stub --agente triagem
    python -m codigo.mcp.stub --agente decisao --log outro/caminho.jsonl
    python -m codigo.mcp.stub --agente todos

O transporte é stdio: quem inicia o processo é o cliente MCP. Na partida o stub grava no log a
abertura dos quatro incidentes, se eles ainda não estiverem lá.

`--agente` é obrigatório. Com `triagem`, `decisao` ou `execucao`, o servidor só expõe as tools
da linha desse agente e registra o nome dele em cada chamada. O indicado é um processo por
agente, todos sobre o mesmo log. `--agente todos` expõe as nove tools em um processo só e deixa
o campo `agente` do log nulo. Serve para desenvolvimento, e só para isso: com as nove tools, um
mesmo cliente propõe e executa, e a separação entre quem lê conteúdo da rede e quem aplica
ações deixa de existir.

O stub não guarda estado na memória. A cada chamada ele lê o log, confere a sequência dos
eventos, decide e grava. Apagar o log zera tudo. Vários processos podem trabalhar sobre o mesmo
arquivo onde existe `fcntl` (Linux e macOS), porque cada chamada trava o arquivo da leitura à
gravação. No Windows não há essa trava: lá, só um processo por vez pode usar o log.

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
| `propor_acao(id, acao, alvo, parametros, justificativa)` | decisão | A proposta, com o risco, os motivos quando o risco é alto e se exige aprovação |
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
que separa DoS de DDoS pela quantidade de origens. Os agentes usam `categoria`. Os endereços de
`origens` e `destinos` são endereços IP validados, e o `nome` de cada feature é uma das 39
colunas do extrator.

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
            "parametros": [{"nome": "duracao", "descricao": "Prazo da medida, em minutos (número inteiro, de 1 a 525.600)", "obrigatorio": false}],
            "regra": "Risco baixo quando o alvo é origem do incidente, a duracao é de até 15 minutos e o incidente tem menos de 5 medidas de risco baixo ativas: o agente de execução aplica sem aprovação. Fora disso (sem duracao, duracao maior, alvo que não consta do incidente, alvo que é destino do incidente, isto é, o dispositivo atacado, endereço protegido pela política ou limite de medidas atingido), risco alto: só com aprovação humana.",
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
A consulta tem até 2.000 caracteres.

**`propor_acao`**, com uma ação do catálogo

```json
{"id": "inc-0001", "acao": "bloquear_ip", "alvo": "203.0.113.7", "parametros": {"duracao": 10},
 "justificativa": "Origem com mais quadros no incidente."}
```
```json
{"id": "prop-0001", "incidente": "inc-0001", "acao": "bloquear_ip", "alvo": "203.0.113.7",
 "parametros": {"duracao": 10}, "justificativa": "Origem com mais quadros no incidente.",
 "nova": false, "risco": "baixo", "motivos_de_risco_alto": [], "exige_aprovacao": false,
 "estado": "liberada"}
```

O mesmo bloqueio de 10 minutos em um endereço que não consta do incidente, no gateway ou no
dispositivo atacado não é recusado: volta com `"risco": "alto"`, `"exige_aprovacao": true`,
`"estado": "aguardando_aprovacao"` e, em `motivos_de_risco_alto`, o porquê. Com
`"alvo": "192.168.137.20"`, que é o destino do flood:

```json
{"id": "prop-0003", "incidente": "inc-0001", "acao": "bloquear_ip", "alvo": "192.168.137.20",
 "parametros": {"duracao": 10}, "justificativa": "Destino do flood.", "nova": false, "risco": "alto",
 "motivos_de_risco_alto": [{"codigo": "alvo_e_destino_do_incidente",
                            "descricao": "O alvo é destino do incidente, isto é, o dispositivo atacado, e esta ação só é de risco baixo sobre uma origem."}],
 "exige_aprovacao": true, "estado": "aguardando_aprovacao"}
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
 "nova": true, "risco": "alto",
 "motivos_de_risco_alto": [{"codigo": "acao_nova", "descricao": "A ação é nova, fora do catálogo."}],
 "exige_aprovacao": true, "estado": "aguardando_aprovacao"}
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

O catálogo de base é o ponto de partida, não um limite.

| Ação | Alvo | Parâmetros | Risco |
|---|---|---|---|
| `limitar_taxa` | Endereço IP | `duracao`, em minutos, obrigatória | Baixo com `duracao` de até 60, sobre origem ou destino do incidente, se as condições abaixo valerem. Senão, alto |
| `bloquear_ip` | Endereço IP de origem | `duracao`, em minutos, opcional | Baixo com `duracao` de até 15, sobre origem do incidente, se as condições abaixo valerem. Sem prazo, com prazo maior ou sobre destino, alto |
| `isolar_dispositivo` | Endereço IP do dispositivo | nenhum | Sempre alto |
| `revogar_credencial` | `usuario@endereco` | nenhum | Sempre alto |
| Ação nova | Texto de uma linha | `descricao`, `passos`, `efeito_esperado`, `como_desfazer` e, se houver, `fonte` | Sempre alto |

O risco não depende só do nome da ação e da duração. Uma proposta é de risco baixo quando
todas estas condições valem:

1. a política marca a ação como de risco baixo e a `duracao` cabe no prazo máximo dela;
2. o alvo faz parte do incidente, na versão mais recente dele, no papel que a política aceita
   para a ação: em `limitar_taxa`, uma das `origens` ou um dos `destinos`; em `bloquear_ip`, só
   uma das `origens`;
3. o incidente está aberto;
4. o alvo não é um endereço protegido (na política de exemplo, o gateway e a máquina de captura);
5. o incidente tem menos de 5 medidas de risco baixo ativas.

O destino do incidente é o dispositivo atacado. Limitar a taxa dele o mantém em serviço.
Bloqueá-lo o tira do ar, que é o que o ataque quer, e por isso o bloqueio de um destino é de
risco alto com qualquer prazo. O endereço que aparece nas origens e nos destinos conta como
destino: o dispositivo atacado responde ao ataque, e as respostas podem pô-lo entre as origens.

Quando alguma das condições falha, a proposta não é recusada: é registrada como de risco alto e
fica aguardando a pessoa. As exceções, que são recusadas, estão na tabela de recusas: endereço
especial como alvo, proposta para incidente encerrado e fila de aprovação cheia.

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
| `alvo_protegido` | O alvo é um endereço protegido pela política. | Ação de base sobre o gateway ou a máquina de captura |
| `orcamento_de_risco_baixo_esgotado` | O incidente já tem o máximo de medidas de risco baixo ativas. | Ação que seria de risco baixo, com 5 medidas de risco baixo ativas no incidente |

Os códigos são estáveis: é por eles que o código dos agentes e a interface web decidem. A frase
é para a pessoa. As duas colunas estão em `contrato.json`, em `motivos_de_risco_alto`. Nas ações
que são sempre de risco alto, os motivos do alvo (`alvo_fora_do_incidente` e `alvo_protegido`)
também saem, para quem aprova o isolamento de um dispositivo saber que ele é o gateway ou que é
alheio ao incidente. O alvo de uma ação nova é texto livre e não é conferido.

Ação de risco baixo já nasce liberada, e o agente de execução a aplica sem aprovação. Na hora
de executar, o risco é calculado de novo, com a política e o incidente daquele momento: propor
várias medidas antes e executar depois não contorna o limite de 5, e uma proposta de risco
baixo não executa depois que o incidente encerra.

Os números (60 e 15 minutos, 5 medidas, 10 propostas pendentes), os alvos em que cada ação é de
risco baixo (`alvos_de_risco_baixo`, com `"origens"` ou `"origens_e_destinos"`), os endereços
protegidos e as redes locais ficam em `politica.toml`. Três regras ficam no código e o arquivo
não as baixa: `isolar_dispositivo`, `revogar_credencial` e toda ação nova são sempre de risco
alto. Um `politica.toml` que marque uma das duas primeiras como de risco baixo é recusado na
leitura.

### Fila de aprovação

Cada incidente tem no máximo 10 propostas aguardando aprovação ao mesmo tempo
(`propostas_aguardando_aprovacao_por_incidente`, em `politica.toml`). A proposta de risco alto
que seria a décima primeira é recusada, com o motivo `limite_de_propostas_pendentes` e uma
mensagem que diz quantas estão na fila:

```
O incidente inc-0001 já tem 10 propostas aguardando aprovação, que é o máximo aceito pela política, e esta proposta não foi registrada. Uma nova proposta de risco alto só entra depois que uma pessoa aprovar ou rejeitar alguma das pendentes.
```

A vaga abre quando a pessoa aprova ou rejeita uma das pendentes. A proposta de risco baixo não
espera ninguém e não entra na conta. O teto existe porque a fila é lida por uma pessoa: sem ele,
um agente enganado por conteúdo vindo da rede poderia registrar propostas sem parar. Ele também
fecha o caminho que o limite de 5 medidas abria, em que cada proposta além do limite virava de
risco alto e ia para a fila.

O nome de uma ação nova usa letras minúsculas, números e sublinhado, como `ativar_syn_cookies`,
e tem até 60 caracteres. Uma ação nova aprovada e aplicada pode ser promovida ao catálogo pela
pessoa. Depois disso ela aparece em `consultar_mitigacoes`, continua de risco alto e é proposta
com `parametros` vazio: os passos e a forma de desfazer são os do catálogo, e a proposta que
trouxer qualquer parâmetro é recusada.

No ambiente simulado, aplicar uma ação é gravar um evento. O prazo fica registrado, mas a
medida não expira sozinha: ela vale até ser desfeita.

### Limites de texto e de alvo

Quem chama as tools é um modelo de linguagem, e o que ele escreve chega a uma pessoa, na tela
de aprovação, e ao log. Por isso:

- Todo texto tem uma linha só. Caractere de controle (ESC, BEL, NUL, tabulação, quebra de
  linha), separador de linha do Unicode (U+0085, U+2028, U+2029) e inversão de direção do texto
  (U+202A a U+202E, U+2066 a U+2069) são recusados. Só o texto da recomendação e os trechos da
  base aceitam quebra de linha, para separar parágrafos.
- Texto curto tem até 200 caracteres: identificadores, `alvo`, `fonte`, títulos. Texto longo tem
  até 2.000: `justificativa`, `descricao`, cada passo, `efeito_esperado`, `como_desfazer`. Uma
  ação nova tem de 1 a 20 passos.
- `duracao` é um número inteiro de 1 a 525.600 minutos (um ano).
- O alvo de uma ação de base é um endereço IP sem zona: `fe80::1%eth0` é recusado, porque o que
  vem depois de `%` é texto livre. IPv4 escrito como IPv6 (`::ffff:192.168.137.1`) vira o IPv4.
  Em `revogar_credencial`, o usuário usa letras sem acento, números, ponto, hífen e sublinhado,
  tem até 64 caracteres e não começa por ponto nem por hífen.
- A mensagem de recusa mostra no máximo um trecho escapado do que veio, e o evento `recusa`
  guarda os argumentos cortados quando eles passam do tamanho do contrato.

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
| `alvo_malformado` | Alvo fora do formato que a ação pede, com zona de IPv6 ou grande demais |
| `alvo_nao_permitido` | Alvo que é endereço de loopback, não especificado, broadcast, multicast ou link-local |
| `incidente_encerrado` | Proposta para incidente que já foi encerrado |
| `limite_de_propostas_pendentes` | Proposta de risco alto para incidente que já tem 10 propostas aguardando aprovação |
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

Aprovar e promover mostram a proposta inteira, com os motivos do risco alto e todos os
parâmetros, e só gravam depois que a pessoa digita `sim`:

```
prop-0002  incidente inc-0001  risco alto
  motivos do risco alto:
    - acao_nova: A ação é nova, fora do catálogo.
  ação: ativar_syn_cookies (nova, fora do catálogo)
  alvo: 192.168.137.20
  justificativa: O bloqueio de uma origem não resolveu.
  descrição: Ativa SYN cookies no dispositivo atacado.
  passos:
    1. Ativar SYN cookies na pilha TCP de 192.168.137.20.
  efeito esperado: A fila de conexões pendentes deixa de esgotar.
  como desfazer: Desativar SYN cookies na pilha TCP de 192.168.137.20.
Aprovar prop-0002? Com a aprovação, o agente de execução pode aplicar a ação acima. Digite sim para confirmar:
```

Qualquer outra resposta encerra o comando sem gravar nada. Sem terminal interativo, o comando
não aprova nem promove, a não ser com `--sim`, que dispensa a pergunta e existe para testes e
roteiros. Rejeitar não libera nada e por isso não pede confirmação. Se a proposta mudar entre a
tela e a gravação, nada é gravado.

Em uma ação de base que aceita prazo, a linha `duracao` aparece sempre, com a unidade:
`duracao: 600 minutos` ou `duracao: sem prazo, até a medida ser desfeita`.

O log é entrada, e o comando não confia nele para escrever na tela: tudo o que não é imprimível
sai escapado. Uma sequência de terminal gravada em um parâmetro aparece como `\x1b[3A`, em vez
de mover o cursor e trocar o que a pessoa lê.

Se o stub foi iniciado com `--log`, passe o mesmo `--log` ao comando.

## Log de eventos

O log fica em `dados/eventos/eventos.jsonl`, fora do git, ou no caminho dado em `--log`. É um
arquivo de texto com um objeto JSON por linha, só de acréscimo. Os campos comuns são `id`,
`instante`, `tipo`, `incidente` (nulo quando não há) e `dados`, cujo formato depende do tipo.

| Tipo | Quem grava | `dados` |
|---|---|---|
| `janelas_classificadas` | classificador (no stub, a partida) | Janelas do lote e contagem por categoria |
| `incidente_aberto`, `incidente_atualizado`, `incidente_encerrado` | política de acionamento (no stub, a partida e `verificar_efeito`) | O incidente inteiro |
| `llm_chamada` | agentes, pelo `GravadorDoAgente` | Agente, modelo, tokens de entrada e de saída, duração |
| `tool_chamada` | servidor | Agente, nome da tool, argumentos, resultado resumido, duração |
| `recomendacao_emitida` | agente de decisão, pelo `GravadorDoAgente` | Agente, texto e propostas ligadas |
| `acao_proposta` | servidor | A proposta, com os motivos quando o risco é alto |
| `acao_aprovada`, `acao_rejeitada` | comando `aprovar` | Proposta, canal e motivo |
| `acao_executada`, `acao_desfeita` | servidor | A execução |
| `efeito_verificado` | servidor | Execução, incidente, resultado e observação |
| `catalogo_ampliado` | comando `aprovar --promover` | Proposta e a ação promovida |
| `recusa` | servidor | Agente, tool, argumentos, motivo e mensagem |

Uma chamada de tool atendida grava `tool_chamada` e, em seguida, os eventos que ela produziu.
Uma chamada recusada grava só `recusa`. As tools sem identificador (`consultar_mitigacoes`,
`pesquisar_solucoes` e `consultar_estado`) ficam registradas no incidente da chamada anterior
do mesmo processo.

Os argumentos vão para o log como vieram quando cabem no contrato. Texto maior que 2.000
caracteres, lista ou objeto com mais de 20 itens, estrutura com mais de 4 níveis e número que o
leitor do log não aceitaria são gravados cortados, com a marca `[cortado: ...]`.

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

O gravador recusa qualquer outro tipo de evento, recusa evento em nome de outro agente e recusa
recomendação que cite proposta que não existe. `Registro`, que aceita todos os eventos, é do
servidor e do comando de aprovação: o código dos agentes não o usa.

O estado das propostas, das aprovações e das medidas ativas sai do log:
`codigo.mcp.acoes.reconstruir(eventos)`. A reconstrução confere cada evento no ponto em que ele
aparece:

- identificador de proposta e de execução é único;
- aprovação e rejeição só valem para proposta que aguarda aprovação;
- execução só vale para proposta liberada ou aprovada, e precisa ser a aplicação do que a
  proposta descreve;
- nenhum evento cita proposta ou execução que não existe;
- a proposta nasce no estado que o risco dela pede, e nunca como de risco baixo se a ação é das
  que são sempre de risco alto;
- a proposta de risco alto traz ao menos um motivo, a de risco baixo não traz nenhum, e cada
  motivo vem uma vez só, com a frase que o contrato dá ao código;
- o incidente abre uma vez e não volta a aberto depois de encerrado.

A violação levanta `LogInvalido` (um `ValueError`), com o arquivo e a linha, como em
`eventos.jsonl, linha 14: acao_aprovada fora de lugar: a proposta prop-0001 não aguarda
aprovação: está executada`. Além disso, `executar_acao` não confia no campo `estado` lido: só
executa proposta que exige aprovação se o evento de aprovação estiver no log, e calcula de novo
o risco da proposta de risco baixo.

`exemplos/incidente_flood.jsonl` é um log completo e versionado, com os 15 tipos de evento, para
o modo replay da interface web.

## Arquivos gerados

    python -m codigo.mcp.tipos                    # gera contrato.json a partir de tipos.py
    python -m codigo.mcp.roteiro --sobrescrever   # gera exemplos/incidente_flood.jsonl

Os dois têm teste: se `tipos.py`, os cenários ou o roteiro mudarem e o arquivo não for gerado
de novo, o `pytest` falha. O roteiro não grava por cima de um arquivo que já existe sem
`--sobrescrever`, nem no caminho padrão, nem no de `--saida`.

## Versão do contrato

A versão fica em `contrato.json`, no campo `versao`, e sai de `VERSAO`, em `tipos.py`. A atual é
a 0.2.0. O que mudou em relação à 0.1.0, para quem já usava o stub:

- `Proposta` ganhou o campo obrigatório `motivos_de_risco_alto`. Quem lê a resposta de
  `propor_acao` ou o evento `acao_proposta` passa a recebê-lo sempre, vazio quando o risco é
  baixo. O resumo de `propor_acao` em `tool_chamada` traz os códigos.
- `bloquear_ip` sobre um destino do incidente deixou de ser de risco baixo: a proposta fica
  aguardando aprovação, com o motivo `alvo_e_destino_do_incidente`. `limitar_taxa` não mudou.
- `propor_acao` pode ser recusada com o motivo novo `limite_de_propostas_pendentes`.
- `politica.toml` ganhou `alvos_de_risco_baixo` nas ações de risco baixo e
  `propostas_aguardando_aprovacao_por_incidente` em `[limites]`. Um arquivo de política sem
  essas chaves é recusado na leitura.
- Um log gravado com a 0.1.0 não é lido pela 0.2.0, porque as propostas dele não trazem os
  motivos. Apague o log e suba o stub de novo.

## Limites do stub

O que este desenho garante por código está nas seções acima. O que ele não garante está aqui,
para que o servidor de verdade não herde o limite sem saber.

**Quem consegue escrever no arquivo de log consegue aprovar.** A aprovação é uma linha
`acao_aprovada` no log. A conferência da sequência recusa a linha malformada, a repetida e a
que cita proposta que não existe, mas uma linha bem formada, acrescentada ao arquivo com um
`echo`, aprova a proposta. O `GravadorDoAgente` impede que o código dos agentes faça isso por
engano, e só isso: ele é uma restrição de interface, e o processo de um agente que tenha acesso
de escrita ao arquivo pode abri-lo diretamente. No stub, o servidor, o comando de aprovação e os
agentes escrevem no mesmo arquivo, com o mesmo usuário. O servidor de verdade precisa de um
canal de decisão que o processo do agente não escreve. Há três caminhos: gravar as decisões em
um arquivo de outro dono, que o agente só lê; assinar cada decisão com uma chave que só o canal
da pessoa tem, e conferir a assinatura ao reconstruir o estado; ou fazer do servidor o único
escritor do log, com os agentes e a interface falando só com ele. O mesmo vale para `--sim` e
para `--agente todos`: são opções da linha de comando, e quem pode rodar comandos na máquina
pode usá-las.

O que mais fica de fora deste trabalho:

- **Trava de arquivo no Windows.** A gravação usa `fcntl.flock`, que não existe no Windows. Lá
  não há trava, e dois processos sobre o mesmo log podem repetir identificadores. Vários
  processos no mesmo log só são seguros no Linux e no macOS.
- **Validade de uma aprovação no tempo.** Uma proposta aprovada pode ser executada a qualquer
  momento depois, inclusive com o incidente já encerrado. A aprovação não vence.
- **Expiração do prazo.** A `duracao` fica registrada, mas a medida não expira sozinha no
  ambiente simulado. Por isso uma medida de risco baixo conta para o limite de 5 até ser
  desfeita.
- **Motivos e teto de pendentes na leitura do log.** A reconstrução confere que a proposta de
  risco alto traz motivo e que a frase é a do contrato, mas não refaz a conta do risco: os
  motivos gravados são os do momento da proposta, com a política e o incidente de então. O teto
  de 10 propostas pendentes vale na hora de propor, e a leitura do log não o confere.
- **Dependências transitivas.** O `requirements.txt` fixa as dependências diretas. As que elas
  trazem não estão fixadas nem conferidas por hash.
- **Histórico do que já foi tentado.** Quando uma ação não resolve, o agente de decisão é
  chamado de novo, mas não há tool que devolva as propostas e os efeitos anteriores do
  incidente. Hoje quem monta esse histórico é o código do agente, a partir do log.
- **Marca de origem contra injeção de prompt.** As respostas das tools não dizem, campo a
  campo, o que é dado do sistema e o que é texto vindo de fora. O stub limita o tamanho e os
  caracteres desses textos, mas não impede que uma instrução escrita em linguagem natural
  chegue ao modelo. No servidor de verdade, estes campos carregam texto de fora e devem ser
  marcados como não confiáveis antes de entrar no prompt:
  - `Trecho.titulo` e `Trecho.texto`, em `consultar_mitigacoes` e `pesquisar_solucoes`: vêm
    dos documentos da base e, se a busca na internet for ligada, de páginas de terceiros;
  - `AcaoDoCatalogo.descricao`, `passos`, `efeito_esperado`, `como_desfazer`, `fonte` e `alvo`
    das ações promovidas: foram escritos por um agente de decisão em uma sessão anterior e
    voltam para todas as sessões seguintes, em qualquer categoria;
  - `Proposta.justificativa`, `Proposta.alvo` e `Proposta.parametros` de ação nova: texto do
    agente de decisão;
  - `Execucao.alvo` e `Execucao.parametros`, em `executar_acao`, `desfazer_acao` e
    `consultar_estado`: é por aqui que texto escrito pelo agente de decisão chega ao agente de
    execução, que em princípio não lê conteúdo de fora;
  - `Recusa.mensagem`, que repete um trecho do argumento recusado;
  - `Incidente.origens`, `Incidente.destinos`, `Janela.origem` e `Janela.destino`: vêm dos
    pacotes, e por isso são endereços IP validados, e não texto;
  - `Recomendacao.texto` e `Decisao.motivo`, que a interface web vai mostrar.

## O que é de mentira

- Os incidentes, as janelas e os efeitos das ações vêm de `cenarios.py`. Os números são
  ilustrativos e não podem ser citados como resultado.
- Os documentos de `base_provisoria/` são provisórios e serão substituídos pelo levantamento de
  mitigações da equipe.
- Nenhuma ação toca a rede. O ambiente é simulado, e aplicar ou desfazer é gravar um evento.
- A busca de `pesquisar_solucoes` é por palavras, só na base local. A busca na internet fica
  desligada por padrão, como decidido na especificação: neste trabalho não há código que a
  ligue, e `fonte` é sempre `base_local`.
