# Figuras do artigo

Cada figura fica aqui em PNG (300 dpi) e em PDF, ao lado da fonte editável que a gera. Os gráficos
são scripts Python que leem os arquivos versionados em `experimentos/resultados/`, sem nenhum
número escrito à mão; os diagramas são fontes Mermaid (`.mmd`). Todos os comandos são dados a
partir da raiz do repositório, com o ambiente do `requirements.txt` e do `requirements-figuras.txt`
ativo (`pip install -r requirements.txt -r requirements-figuras.txt`).

Um comando só regera as figuras que o artigo em LaTeX (`artigo/latex/`) inclui, os gráficos e os
diagramas:

    python -m artigo.figuras                        # tudo
    python -m artigo.figuras graficos               # ou só uma parte: graficos, diagramas

| Figura | Script ou fonte | Dados usados | Comando para regerar |
|---|---|---|---|
| 1. Arquitetura do sistema | `arquitetura.mmd` | ROADMAP.md e `codigo/mcp/README.md` (descrição, sem dados) | `python -m artigo.figuras.diagramas arquitetura` |
| 2. Fluxo de um incidente | `fluxo_incidente.mmd` | eventos do contrato (`codigo/mcp/contrato.json`), na ordem do log `codigo/mcp/exemplos/incidente_flood.jsonl` | `python -m artigo.figuras.diagramas fluxo_incidente` |
| 3. Matriz de confusão do modelo do sistema, no ponto de operação | `matriz_confusao.py` | `experimentos/resultados/matrizes_confusao/regerado_janela_100_ponto.csv` | `python -m artigo.figuras.matriz_confusao` |
| 4. Teste da janela | `teste_da_janela.py` | `experimentos/resultados/teste_da_janela.csv` | `python -m artigo.figuras.teste_da_janela` |
| 5. Janelas sem atacante | `janelas_sem_atacante.py` | `experimentos/resultados/janelas_sem_atacante.csv` | `python -m artigo.figuras.janelas_sem_atacante` |

A numeração segue a ordem em que o artigo em LaTeX inclui as figuras.

As capturas da interface não são figuras do artigo e não ficam nesta pasta. Para os slides, a
interface se fotografa em modo replay com o log de uma execução real que possa ser publicada (como
abrir o log está no `frontend/README.md`, em "Log do replay"). O log de exemplo do stub
(`codigo/mcp/exemplos/incidente_flood.jsonl`) é só dos testes e não serve para captura: a interface
não mostra dado simulado (decisão de 15/10 no `ROADMAP.md`).

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
- Diagramas: Node.js, para o `npx` rodar o mermaid-cli, com a versão fixada em `diagramas.py`.
  Na primeira execução, o `npx` baixa o mermaid-cli e o navegador que ele usa para desenhar.
  `python -m artigo.figuras.diagramas`, sem nome, exporta todos os `.mmd` da pasta.

## Gráfico de análise fora do artigo

`pcap_fora_do_treino.py` desenha o recall de cada um dos 21 pcaps retirados nas rodadas de teste
(`experimentos/resultados/rodadas_normalizadas_pcap_fora.csv`, linhas do modelo do sistema), no
trecho de teste do pcap e na média das sementes 42, 1 e 2, em duas barras: com o começo do pcap no
treino (corte por tempo, hachurada) e com o pcap inteiro fora do treino. As duas usam a categoria
mais provável, que é o ponto de operação do modelo do sistema. Somadas as janelas dos pcaps de cada
categoria, as barras hachuradas reproduzem a coluna de recall da Tabela 1 do artigo, menos em
DDoS+DoS, em que só 4 pcaps foram retirados (93,2% contra 98,4%); o título de cada painel, com o
pcap fora, reproduz a última coluna. O gráfico não está no artigo nem no `python -m artigo.figuras`, e o PNG e o PDF não
são versionados (`.gitignore`): `python -m artigo.figuras.pcap_fora_do_treino` grava os dois nesta
pasta quando for preciso.

O PDF dos gráficos sai sem data de criação, e por isso os mesmos dados geram o mesmo arquivo.
