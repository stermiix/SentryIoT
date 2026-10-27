# Figuras do artigo

Cada figura fica aqui em PNG (300 dpi) e em PDF, ao lado da fonte editável que a gera. Os gráficos
são scripts Python que leem os arquivos versionados em `experimentos/resultados/`, sem nenhum
número escrito à mão; os diagramas são fontes Mermaid (`.mmd`). Todos os comandos são dados a
partir da raiz do repositório, com o ambiente do `requirements.txt` e do `requirements-figuras.txt`
ativo (`pip install -r requirements.txt -r requirements-figuras.txt`).

Um comando só regera tudo, os gráficos, os diagramas e as capturas da interface:

    python -m artigo.figuras                        # tudo
    python -m artigo.figuras graficos               # ou só uma parte: graficos, diagramas, capturas

| Figura | Script ou fonte | Dados usados | Comando para regerar |
|---|---|---|---|
| 1. Arquitetura do sistema | `arquitetura.mmd` | ROADMAP.md e `codigo/mcp/README.md` (descrição, sem dados) | `python -m artigo.figuras.diagramas arquitetura` |
| 2. Fluxo de um incidente | `fluxo_incidente.mmd` | eventos do contrato (`codigo/mcp/contrato.json`), na ordem do log `codigo/mcp/exemplos/incidente_flood.jsonl` | `python -m artigo.figuras.diagramas fluxo_incidente` |
| 3. Matriz de confusão do modelo do sistema, no ponto de operação | `matriz_confusao.py` | `experimentos/resultados/matrizes_confusao/regerado_janela_100_ponto.csv` | `python -m artigo.figuras.matriz_confusao` |
| 4. Teste da janela | `teste_da_janela.py` | `experimentos/resultados/teste_da_janela.csv` | `python -m artigo.figuras.teste_da_janela` |
| 5. Janelas sem atacante | `janelas_sem_atacante.py` | `experimentos/resultados/janelas_sem_atacante.csv` | `python -m artigo.figuras.janelas_sem_atacante` |
| 6. Recall de cada pcap no treino e fora dele (rodadas de teste) | `pcap_fora_do_treino.py` | `experimentos/resultados/rodadas_normalizadas_pcap_fora.csv`, configuração 5 | `python -m artigo.figuras.pcap_fora_do_treino` |

A numeração segue a ordem em que o `artigo/esqueleto.md` cita as figuras.

As capturas da interface ainda não têm número, porque o esqueleto não as cita:

| Captura | Como foi gerada | Dados usados | Como refazer |
|---|---|---|---|
| `interface_fila.png`: visão geral, com o funil, os cartões e a fila de incidentes (`#/visao-geral`) | Interface em modo replay, no último evento do log, janela de 1440 × 1220 px e resolução 2x, pelo Chrome sem janela (`capturas.py`) | `codigo/mcp/exemplos/incidente_flood.jsonl`, o log de exemplo do MCP | `python -m artigo.figuras capturas`: copia o log para `frontend/public/dados/`, sobe o `vite` com `VITE_LOG_DE_EVENTOS` e fotografa as duas telas |
| `interface_detalhe.png`: detalhe do `inc-0001` (`#/incidentes/inc-0001`) | Igual à anterior, com janela de 1440 × 900 px | Igual à anterior | Igual à anterior |

Os números das capturas são ilustrativos, do roteiro do stub MCP, como a própria tela avisa, e não
podem ser citados como resultado. As horas aparecem no fuso de quem abre a página.

**A matriz de confusão é a do modelo do sistema.** É o modelo da configuração 5, treinado com o
fundo da parte de treino dos pcaps de ataque como benigno, no ponto de operação escolhido na
validação, na parte de teste do corte por tempo (decisões de 13/10/2026 no `ROADMAP.md`;
`experimentos/resultados/regeracao.md`). Na validação, a categoria mais provável (argmax) venceu o
melhor limiar (t = 0,61), e a matriz é a do argmax. A legenda precisa trazer as ressalvas dos controles: a
linha Benign é de um único pcap fora do treino, e o alarme falso muda conforme o pcap benigno que
fica de fora (`ponto_de_operacao.md`); com o pcap inteiro fora do treino, o recall é menor que o
da diagonal em todas as categorias com mais de um pcap, e bem menor em Recon, Spoofing e Mirai
(`rodadas_normalizadas.md`); e o Spoofing depende de um artefato da captura (`rodadas_de_teste.md`,
rodada f). Quando `python -m
codigo.classificador.treinar_regerado` regravar o CSV, basta rodar `matriz_confusao.py` de novo.

## Dependências

- Gráficos: `matplotlib` e `pillow`, fixados no `requirements-figuras.txt`, à parte do
  `requirements.txt` para não entrar no CI nem no `pip-audit` dos testes. `estilo.py` guarda o que os gráficos
  têm em comum: fonte serifada (Times New Roman, ou DejaVu Serif onde ela não existir), 16 cm de
  largura, tons de cinza e hachuras para a leitura em preto e branco.
- Capturas: Node.js, com o `npm ci` de `frontend/` (o script o faz se faltar), e o Chrome ou o
  Chromium; outro executável vai na variável `CHROME`. O Chrome roda com um perfil temporário.
- Diagramas: Node.js, para o `npx` rodar o mermaid-cli, com a versão fixada em `diagramas.py`.
  Na primeira execução, o `npx` baixa o mermaid-cli e o navegador que ele usa para desenhar.
  `python -m artigo.figuras.diagramas`, sem nome, exporta todos os `.mmd` da pasta.

**A Figura 6 é das rodadas de teste do modelo do sistema** (configuração 5 de `rodadas_normalizadas.md`). Cada pcap retirado nas rodadas aparece duas vezes, no mesmo trecho de teste e na média das sementes 42, 1 e 2: com o começo dele no treino (a divisão publicada) e com ele inteiro fora do treino. As duas barras usam a categoria mais provável, e não o ponto de operação, e só os 21 pcaps retirados; por isso a barra com o pcap no treino não é a coluna de recall da Tabela 1, e o título de cada painel, somando as janelas dos pcaps, é a última coluna dela. A figura vai com o item "Outra captura da mesma categoria" das Limitações.

O PDF dos gráficos sai sem data de criação, e por isso os mesmos dados geram o mesmo arquivo.
