# Artigo em LaTeX

O artigo do TCC II no template de artigo da FCI (2026), a versão LaTeX do template do Oriente,
baseada no modelo de artigo do abnTeX2 (ABNT NBR 6022). O texto veio do `.docx` do PR 60 (branch
`artigo-introducao-referencial`, commit `de7b90c`), sem correção de conteúdo, e daqui em diante é
escrito e corrigido aqui. O que ainda falta escrever ou conferir fica em `\pendente{...}`, que sai
em vermelho no PDF; nenhuma marca pode sobrar na versão submetida.

## Regras do template

- No máximo **20 páginas, contando as referências**. O CI reprova o PR que passar disso.
- Resumo e abstract com **150 a 250 palavras** cada.
- Citações e referências na ABNT (NBR 6023), pelo `abntex2cite`: `\cite{neto2023}` dá
  "(NETO et al., 2023)" e `\citeonline{neto2023}` dá "Neto et al. (2023)".

O orçamento de palavras por seção fica no comentário do topo de cada arquivo em `secoes/` e na
tarefa 99 do painel. Ele soma cerca de 7.800 palavras, o que cabe nas 20 páginas com as figuras,
as tabelas e as referências.

## Arquivos

```
artigo/latex/
├── artigo.tex        # preâmbulo do template, título, autores e a ordem das seções
├── referencias.bib   # referências (BibTeX); CONFERIR marca o que ainda falta conferir na fonte
├── FCI.png           # logo do cabeçalho, do template
└── secoes/
    ├── resumo.tex, abstract.tex
    ├── 1-introducao.tex
    ├── 2-referencial.tex
    ├── 3-metodologia.tex
    ├── 4-resultados.tex
    └── 5-conclusao.tex
```

As figuras vêm de `../figuras/` (`\graphicspath`), em PDF, geradas pelos scripts de lá. Uma
figura nova se gera lá e se inclui pelo nome, sem copiar para esta pasta.

Só entra na lista de referências o que o texto cita, com `\cite` ou `\citeonline`. Uma entrada do
`referencias.bib` sem citação, como a de Ferrag et al. (2024), fica guardada e não aparece no PDF.
As referências cruzadas usam `\label` e `\ref` (`seção~\ref{sec:mcp}`, `Tabela~\ref{tab:alarme}`),
para a numeração acompanhar quando uma seção, figura ou tabela mudar de lugar.

## Como compilar

- **No GitHub (o caminho padrão):** todo PR que mexe em `artigo/latex/` ou em `artigo/figuras/`
  roda o workflow "Artigo". Ele compila, mostra as palavras por arquivo e o total de páginas no
  resumo do job e guarda o PDF em "Artifacts" (`artigo-pdf`), na página da execução.
- **Na máquina:** com um TeX Live que tenha o abnTeX2 (MacTeX, ou BasicTeX com
  `tlmgr install abntex2`), nesta pasta:

  ```
  latexmk -pdf artigo.tex
  ```

- **No Overleaf:** subir a pasta `artigo/` inteira (por causa de `figuras/`) e escolher
  `latex/artigo.tex` como documento principal.
