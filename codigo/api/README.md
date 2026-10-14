# Servidor fino da interface

Backend em Python (Starlette e uvicorn) que serve a API da interface web. Nesta etapa ele
expõe o chat com o modelo do provedor de LLM configurado; a chave do provedor fica só aqui,
nunca no navegador.

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

Rota sob `/api` que não existe devolve 404 em JSON. Fora de `/api`, se `frontend/dist/`
existir, o servidor serve a interface construída: `/` e qualquer caminho desconhecido devolvem o
`index.html`, e os arquivos da pasta saem com o tipo certo; nada fora da pasta é servido. Sem a
pasta, só a API responde.

Erros vêm como `{"erro": "..."}`, com o nome do campo na mensagem: 400 para corpo que não é
JSON, campo ausente ou com tipo errado, modelo fora da lista permitida ou conversa fora dos
limites; 502 quando o provedor recusa ou não responde (com `codigo`, o status dele, ou nulo);
503 quando falta variável obrigatória (com `faltando`).

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
| `provedor.py` | Cliente de `chat/completions`, só com a biblioteca padrão; o orquestrador vai reaproveitá-lo |
| `prompts.py` | Leitura das skills dos agentes como prompts de sistema |
| `servidor.py` | As rotas, em Starlette |
| `__main__.py` | A linha de comando |
| `test_*.py` | Testes sem rede: o provedor e a abertura da conexão são trocados |
