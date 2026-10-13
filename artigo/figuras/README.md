# Figuras do artigo

Cada figura fica aqui em PNG (300 dpi) e em PDF, ao lado da fonte editável que a gera. Os gráficos
são scripts Python que leem os arquivos versionados em `experimentos/resultados/`, sem nenhum
número escrito à mão; os diagramas são fontes Mermaid (`.mmd`). Todos os comandos são dados a
partir da raiz do repositório, com o ambiente do `requirements.txt` e do `requirements-figuras.txt`
ativo (`pip install -r requirements.txt -r requirements-figuras.txt`).

| Figura | Script ou fonte | Dados usados | Comando para regerar |
|---|---|---|---|
| 1. Arquitetura do sistema | `arquitetura.mmd` | ROADMAP.md e `codigo/mcp/README.md` (descrição, sem dados) | `python -m artigo.figuras.diagramas arquitetura` |
| 2. Fluxo de um incidente | `fluxo_incidente.mmd` | eventos do contrato (`codigo/mcp/contrato.json`), na ordem do log `codigo/mcp/exemplos/incidente_flood.jsonl` | `python -m artigo.figuras.diagramas fluxo_incidente` |
| 3. Matriz de confusão do modelo do sistema, no ponto de operação | `matriz_confusao.py` | `experimentos/resultados/matrizes_confusao/regerado_janela_100_ponto.csv` | `python -m artigo.figuras.matriz_confusao` |
| 4. Teste da janela | `teste_da_janela.py` | `experimentos/resultados/teste_da_janela.csv` | `python -m artigo.figuras.teste_da_janela` |
| 5. Janelas sem atacante | `janelas_sem_atacante.py` | `experimentos/resultados/janelas_sem_atacante.csv` | `python -m artigo.figuras.janelas_sem_atacante` |

A numeração segue a ordem em que o `artigo/esqueleto.md` cita as figuras.

As capturas da interface ainda não têm número, porque o esqueleto não as cita:

| Captura | Como foi gerada | Dados usados | Como refazer |
|---|---|---|---|
| `interface_fila.png`: tela 1, resumo e fila de incidentes | Interface em modo replay, janela de 1440 px de largura e resolução 2x | `frontend/public/dados/incidente_flood.jsonl`, cópia do log de exemplo do MCP | Em `frontend/`, `npm ci` e `npm run dev`; capturar de `http://localhost:5173` até o fim da fila |
| `interface_detalhe.png`: tela 2, detalhe do `inc-0001` | Igual à anterior, só a seção de detalhe, com o primeiro incidente da fila selecionado | Igual à anterior | Igual à anterior, com o `inc-0001` selecionado |

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
  `requirements.txt` para não entrar no CI nem no `pip-audit` dos testes. `estilo.py` guarda o que as três figuras
  têm em comum: fonte serifada (Times New Roman, ou DejaVu Serif onde ela não existir), 16 cm de
  largura, tons de cinza e hachuras para a leitura em preto e branco.
- Diagramas: Node.js, para o `npx` rodar o mermaid-cli, com a versão fixada em `diagramas.py`.
  Na primeira execução, o `npx` baixa o mermaid-cli e o navegador que ele usa para desenhar.
  `python -m artigo.figuras.diagramas`, sem nome, exporta todos os `.mmd` da pasta.

O PDF dos gráficos sai sem data de criação, e por isso os mesmos dados geram o mesmo arquivo.
