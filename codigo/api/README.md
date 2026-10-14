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
- `POST /api/chat`: recebe `{"modelo", "sistema", "mensagens": [{"papel", "conteudo"}]}`, com
  `papel` em `usuario` ou `assistente` e `modelo` vazio para usar o padrão. Chama o provedor sem
  streaming e devolve `{"conteudo", "modelo", "tokens_entrada", "tokens_saida", "tempo_ms"}`.
  Tokens vêm nulos quando o provedor não informa o uso.

Erros vêm como `{"erro": "..."}`: 400 para corpo que não é JSON, campo ausente ou com tipo
errado, ou modelo fora da lista permitida; 502 quando o provedor recusa ou não responde (com
`codigo`, o status dele, ou nulo); 503 quando falta variável obrigatória (com `faltando`).

## Arquivos

| Arquivo | Papel |
|---|---|
| `configuracao.py` | Leitura do `.env` e da configuração do provedor |
| `provedor.py` | Cliente de `chat/completions`, só com a biblioteca padrão; o orquestrador vai reaproveitá-lo |
| `servidor.py` | As rotas, em Starlette |
| `__main__.py` | A linha de comando |
| `test_*.py` | Testes sem rede: o provedor e a abertura da conexão são trocados |
