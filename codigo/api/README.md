# Servidor fino da interface

Backend em Python (Starlette e uvicorn) que serve a API da interface web. Nesta etapa ele
expõe o chat com o modelo do provedor de LLM configurado e a simulação com um pcap, em que cada
incidente passa pelos agentes; a chave do provedor fica só aqui, nunca no navegador.

Todos os comandos são dados a partir da raiz do repositório, com o ambiente do
`requirements.txt` ativo.

## Configuração

Copie `.env.example` para `.env` na raiz (o `.env` é ignorado pelo git) e preencha:

| Variável | Papel | Padrão |
|---|---|---|
| `LLM_BASE_URL` | Base da API compatível com OpenAI, terminando em `/v1` | obrigatória |
| `LLM_API_KEY` | Chave, enviada como `Authorization: Bearer` | obrigatória |
| `LLM_MODEL` | Modelo padrão | obrigatória |
| `LLM_MODELOS_PERMITIDOS` | Modelos que a tela pode escolher, separados por vírgula; o padrão entra sempre na frente | só o `LLM_MODEL` |
| `LLM_CA_BUNDLE` | PEM da CA do provedor, quando o certificado é interno | cadeia do sistema |
| `LLM_TIMEOUT_S` | Prazo de cada chamada ao provedor, em segundos | 300 |
| `LLM_RACIOCINIO` | `ligado` ou `desligado`; vai em `chat_template_kwargs.enable_thinking` | o do provedor |
| `LLM_TEMPERATURA` | Temperatura, de 0 a 2 | o do provedor |
| `LLM_SEMENTE` | Semente, inteiro a partir de 0 | o do provedor |
| `LLM_MAX_TOKENS` | Teto de tokens de saída, inteiro a partir de 1 | o do provedor |

Os quatro parâmetros de geração vão em toda chamada quando definidos; o `.env.example` traz os
valores medidos em 19/10 no gateway interno. Valor fora da faixa impede o servidor de subir.

O orquestrador dos agentes (`python -m codigo.agente`) lê um segundo conjunto, o do modelo de nuvem do
agente de decisão, com as mesmas variáveis e o prefixo `LLM_NUVEM_` (`LLM_NUVEM_BASE_URL`,
`LLM_NUVEM_API_KEY`, `LLM_NUVEM_MODEL` e as opcionais). `LLM_NUVEM_PROVEDORES`, por exemplo `anthropic`, vai em
`provider.only` e restringe os provedores que o OpenRouter pode usar. Este servidor só usa o conjunto `LLM_*`.

Variável já definida no ambiente vence a do arquivo.

## Como subir

    python -m codigo.api                      # 127.0.0.1:8000, lendo o .env da raiz
    python -m codigo.api --host <endereco> --port 8000
    python -m codigo.api --env /outro/.env

No desenvolvimento da interface, o Vite (`npm run dev` em `frontend/`) encaminha `/api` para
`http://127.0.0.1:8000`.

## Rotas

- `GET /api/modelos`: devolve `{"modelos": [...], "padrao": "..."}` a partir da lista
  permitida, sem chamar o provedor.
- `GET /api/prompts`: devolve `{"prompts": [{"nome", "titulo", "texto"}]}` com cada `SKILL.md`
  de `codigo/agente/skills/`, sem o cabeçalho YAML; `nome` é o da pasta e `titulo` é o primeiro
  título do arquivo. É o ponto de partida do prompt de sistema na tela.
- `POST /api/chat`: recebe `{"modelo", "sistema", "mensagens": [{"papel", "conteudo"}]}`, com
  `papel` em `usuario` ou `assistente` e `modelo` vazio para usar o padrão. Chama o provedor sem
  streaming e devolve `{"conteudo", "modelo", "tokens_entrada", "tokens_saida", "tempo_ms"}`.
  Tokens vêm nulos quando o provedor não informa o uso.
- `POST /api/simulacao`: recebe um pcap no corpo, e cada incidente segue para os agentes em
  segundo plano. Ver "Simulação com um pcap", abaixo.
- `GET /api/simulacao/atual`, `POST /api/simulacao/decisao` e `POST /api/simulacao/parar`:
  acompanham a simulação, gravam a decisão da pessoa e param os agentes.

Rota sob `/api` que não existe devolve 404 em JSON. Fora de `/api`, se `frontend/dist/`
existir, o servidor serve a interface construída: `/` e qualquer caminho desconhecido devolvem o
`index.html`, e os arquivos da pasta saem com o tipo certo; nada fora da pasta é servido. Sem a
pasta, só a API responde.

Os erros do chat vêm como `{"erro": "..."}`, com o nome do campo na mensagem: 400 para corpo
que não é JSON, campo ausente ou com tipo errado, modelo fora da lista permitida ou conversa fora
dos limites; 502 quando o provedor recusa ou não responde (com `codigo`, o status dele, ou nulo);
503 quando falta variável obrigatória (com `faltando`).

## Simulação com um pcap

`POST /api/simulacao?nome=<arquivo>&so_teste=1` recebe o pcap cru no corpo, e não num formulário,
e o passa pelo reprodutor de tráfego (`codigo/reprodutor/`): extrator, modelo do sistema e
política de acionamento. Os incidentes vão para um log de eventos novo, e a resposta volta logo
depois da classificação. Em segundo plano, cada incidente segue para o orquestrador
(`codigo/agente/agentes.py`), um por vez e na ordem em que abriu: triagem, decisão, aprovação de
uma pessoa quando o risco é alto, execução, verificação do efeito e sumário. Os agentes rodam na
configuração `local`, com o modelo do `.env`. Um erro num incidente não impede os seguintes.

Em replay, a ação não age sobre o tráfego gravado: a verificação do efeito é simulada e sempre dá
"cessou" (`EFEITOS_DO_REPLAY`, em `codigo/reprodutor/reprodutor.py`). A interface diz isso na
tela da simulação, no detalhe do incidente e no relatório.

- `nome` é o nome do arquivo enviado. Fica só o último trecho do caminho, com caracteres
  seguros, e o padrão é `captura.pcap`. É por ele que `so_teste` acha o pcap no manifesto.
- `so_teste` (`1`, `true` ou `sim`) classifica só o trecho do pcap que ficou fora do treino do
  modelo do sistema, pelo `experimentos/resultados/manifesto_regeracao.json`. As janelas
  anteriores são extraídas, para manter o alinhamento, mas não são classificadas, e a resposta
  as conta em `janelas_puladas`. O pcap que ficou inteiro no teste é lido todo; o que ficou
  inteiro no treino, ou que não está na regeração, recebe 400.
- As rotas da simulação exigem o cabeçalho `X-SentryIoT: interface`, que só a interface manda. Um cabeçalho
  próprio obriga o navegador a pedir licença (CORS) antes de uma página de outro site disparar a
  rota, e o backend não dá essa licença.
- Roda uma simulação por vez, contando o tempo dos agentes. O envio do arquivo vem antes da trava,
  para um cliente lento não segurar a vez dos outros.

A resposta é o resumo do reprodutor: quadros, janelas, janelas por categoria, relógio de
reprodução, trecho lido, modelo, ponto de operação, parâmetros da política de acionamento e os
incidentes, com categoria, confiança, instantes e atraso de detecção. Vêm ainda:

| Campo | O que traz |
|---|---|
| `log`, `cenarios` | Os caminhos do log de eventos e dos cenários gravados, relativos à raiz do repositório |
| `eventos` | O texto do log de eventos, em JSONL |
| `agentes` | `estado` (`rodando`, `parando`, `concluidos`, `interrompidos`, `sem_modelo` ou `sem_incidentes`), `configuracao`, `modelo`, `motivo` (por que não rodaram, quando falta o modelo) e `incidentes`, com `id`, `situacao` (`na_fila`, `em_andamento`, `concluido`, `erro` ou `interrompido`), `desfecho` do orquestrador e `erro` |

`GET /api/simulacao/atual` devolve `{"simulacao": ...}` com a mesma forma, o log como está agora e
os agentes como estão agora, ou nulo se o servidor não rodou nenhuma simulação desde que subiu. A
interface lê essa rota a cada 2 segundos enquanto os agentes rodam, e também ao abrir a página, para
um recarregamento não largar a simulação.

`POST /api/simulacao/decisao` recebe `{"tipo", "id", "motivo"}`, com `tipo` em `aprovar`, `rejeitar`
ou `resolvido`; `id` é a proposta nos dois primeiros e o incidente no último. A decisão vai para o
log pelo mesmo caminho do comando `python -m codigo.mcp.aprovar`, com o canal `interface` e o usuário
do sistema dono do processo. Nenhum agente chega a esta rota. Rejeitar com motivo devolve a vez ao
agente de decisão. Sem agentes rodando, a decisão não teria efeito e recebe 409, assim como o pedido
que o servidor recusa (proposta que não existe, por exemplo).

`POST /api/simulacao/parar` encerra na hora a espera por uma pessoa, e nenhum incidente novo começa.
Uma chamada ao modelo já em curso termina antes, por isso os agentes passam por `parando`.

Cada simulação grava em `dados/eventos/simulacoes/<instante>-<pcap>/`, fora do git, o
`eventos.jsonl`, o `eventos.cenarios.json` e o `resumo.json`, que é a resposta sem `eventos`, com o
estado final dos agentes. Os
três trazem endereços da rede, e por isso a pasta só abre para o dono (700) e os arquivos só são
lidos e escritos por ele (600). O pcap enviado vai para um arquivo temporário, apagado no fim,
com sucesso ou com erro.

Os erros vêm em `{"erro": "..."}`: 400 para corpo vazio, arquivo que o extrator não lê (pcapng,
outro formato ou outro tipo de enlace), `so_teste` sem trecho fora do treino ou decisão fora do
formato; 403 sem o
cabeçalho da interface; 409 com outra simulação em andamento; 413 para pcap acima de 600 MB (o
extrator lê cerca de 160 mil quadros por segundo, e um pcap desse tamanho leva perto de um
minuto); 500, sem detalhe, para falha do próprio backend; e 503 sem o modelo do sistema em
`modelos/rf_regerado_janela_100.joblib`. Sem o modelo, o servidor sobe com um aviso, e só a
simulação fica desligada. O JSON do ponto de operação precisa estar ao lado do modelo e ser dele
(o SHA-256 é conferido); se não for, a simulação falha com 500.

## Limites

Conferidos antes de qualquer chamada ao provedor, para o custo e o servidor não escaparem:

| O quê | Limite |
|---|---|
| Prompt de sistema | 20.000 caracteres |
| Cada mensagem | 8.000 caracteres |
| Mensagens no histórico | 40, e a última precisa ser da pessoa |
| Soma de sistema e mensagens | 80.000 caracteres |

## Implantação no servidor da equipe

Uma URL só, alcançada pela rede privada do Tailscale. Nenhuma porta aberta para a internet: o
chat gasta crédito do provedor a cada mensagem e, quando o sistema completo subir, a interface
terá os botões de aprovar e desfazer ações na rede.

1. Clonar o repositório e criar o ambiente (`python3 -m venv .venv`, `pip install -r
   requirements.txt`), com Node.js 20 ou mais recente para o build.
2. Copiar `.env.example` para `.env`, preencher e deixar só o dono ler: `chmod 600 .env`. Se o
   provedor usa certificado de CA interna, guardar o PEM fora do repositório e apontar
   `LLM_CA_BUNDLE` para ele.
3. Construir a interface: `cd frontend && npm ci && npm run build`.
4. Subir, na raiz, no endereço do Tailscale da máquina (e não em `0.0.0.0`):
   `python -m codigo.api --host <endereço Tailscale> --port 8000`.
5. Conferir de outra máquina da rede privada: `http://<nome-no-tailscale>:8000/#chat`.

Para o processo sobreviver ao fim da sessão, rode-o sob um gerenciador do sistema (systemd,
launchd ou equivalente) com o diretório de trabalho na raiz do repositório.

## Arquivos

| Arquivo | Papel |
|---|---|
| `configuracao.py` | Leitura do `.env` e da configuração do provedor |
| `provedor.py` | Cliente de `chat/completions`, só com a biblioteca padrão; o orquestrador usa o mesmo |
| `prompts.py` | Leitura das skills dos agentes como prompts de sistema |
| `simulacao.py` | A simulação com um pcap: o reprodutor, a pasta da simulação, os agentes em segundo plano e a decisão da pessoa |
| `servidor.py` | As rotas, em Starlette |
| `__main__.py` | A linha de comando |
| `test_*.py` | Testes sem rede: o provedor e a abertura da conexão são trocados |
