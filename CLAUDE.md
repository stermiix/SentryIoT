# SentryIoT — TCC II (contexto e regras de trabalho)

Este repositório (`SentryIoT`) é **o TCC de verdade**: código, experimentos, artigo e reports.
O painel de acompanhamento (roadmap) vive na pasta-mãe `RoadMap_TCC/` e **não é o trabalho** —
é o espelho do andamento. Sempre que o trabalho aqui mudar o plano, o roadmap tem que ser
atualizado (ver "Sincronização com o roadmap", abaixo).

## O projeto

**SentryIoT — MultiAgent NIDR.** Sistema de detecção **e resposta** a intrusões em redes IoT que
combina um classificador Random Forest (anomalias em tráfego) com um sistema **multiagente LLM**
integrado via **MCP**, traduzindo alertas técnicos em recomendações de mitigação acionáveis.

- **Instituição:** FCI Mackenzie — TCC II, 2º semestre de 2026.
- **Equipe:** Bernardo Souza Oliveira, Matheus Queiroz Gregorin, José Victor Roling,
  Pedro Henrique Cagnoni Guimarães.
- **Orientador:** Prof. Rodrigo Cardoso Silva.
- **Datasets:** CICIoT2023 (primário, confirmado). **Secundário em definição** — o N-BaIoT,
  declarado no TCC I, não cobre a lacuna que motivaria um segundo dataset: é Mirai/BASHLITE,
  todas as classes volumétricas, sem exfiltração, com 115 features incompatíveis com as 39 do
  CICIoT2023 e sem PCAP distribuído (o que conflita com a Decisão B). Ver `ROADMAP.md`.
- **Stack:** Python, Pandas, scikit-learn, Scapy, (Wireshark), servidor MCP, agente LLM.
- **PoC:** cenários de DDoS, port scan, brute force e exfiltração de dados; comparação entre a
  saída isolada do classificador e a saída integrada (MCP + agentes). **Atenção:** o CICIoT2023
  não tem exfiltração e cobre brute force com uma variante só — o 4º cenário depende de decisão
  pendente com o orientador (`ROADMAP.md`).
- **Métricas:** acurácia, precisão, recall, F1-score e taxa de falso positivo (FPR).

## Correções vindas da banca do TCC I (obrigatórias, valem nota)

O item 5 do orientador é "analisar e avaliar as recomendações da banca". Elas já mudaram o escopo:

1. **NIDS → NDR/NIDR.** O projeto foi reposicionado como detecção **e resposta** (daí "NIDR" no
   nome). Todo texto novo deve usar esse enquadramento, não "NIDS".
2. **Deixar claro o papel do Scapy e do Wireshark.** O avaliador 2 questionou: se o trabalho usa
   datasets, onde entra a captura de pacotes? O Wireshark é mesmo necessário ou o Scapy basta?
   O artigo precisa responder isso explicitamente — decidir e documentar se haverá coleta in loco
   de tráfego IoT real ou se é só dataset (e, nesse caso, justificar as ferramentas ou removê-las).
3. **Riscos de IA em nuvem, custo de tokens e a alternativa on-premises** devem ser discutidos.
4. **Limites de análise por NetFlow vs. PCAP** devem ser discutidos.
5. **Referências a investigar e citar:** Darktrace, Netskope, Vectra AI e o ataque
   *Denial of Wallet* (DoW).

Ao escrever qualquer seção do artigo, verifique quais desses pontos ela deveria endereçar.

## Prazos oficiais do edital (datas absolutas — não negociáveis)

| Marco | Data |
|---|---|
| Cadastro no Oriente + anuência do orientador | 18/08 – 31/08/2026 |
| Requerimento no Portal do Aluno | 01/09 – 21/09/2026 |
| Indicação dos avaliadores da banca | 03/11 – 11/11/2026 |
| **Submissão do artigo + relatório + pôster** | **03/11 – 09/11/2026** |
| Bancas TCC II | 16/11 – 27/11 e 31/11–01/12/2026 |
| **Entrega final + termo de anuência** | **04/12/2026** |
| Postagem das notas | 07/12 – 09/12/2026 |

O artigo tem 10–20 páginas, no template do Oriente. A apresentação tem 15–20 min.

**Restrição que domina o cronograma:** a submissão é no início de novembro, não em dezembro.
As fases técnicas foram comprimidas para terminar até o fim de outubro, com a redação correndo
em paralelo desde já.

## Regras do orientador

1. **Report toda segunda-feira, sem exceção**, com o nome de quem fez cada tarefa.
2. Discussão pelo grupo de WhatsApp; reuniões marcadas quando necessário.
3. Ser proativo — reunião com o orientador sozinha não produz a pesquisa.
4. Escrita do artigo em paralelo com o desenvolvimento, desde já.

Os reports ficam em `reports/` (um arquivo por semana, `AAAA-MM-DD.md`, data da segunda-feira).

## Estrutura do repositório

```
artigo/          # texto do artigo, seções, figuras/
codigo/
  captura/       # coleta/parsing de tráfego (Scapy, PCAP)
  classificador/ # pré-processamento, features, treino e tuning do Random Forest
  mcp/           # servidor MCP que expõe as predições como tools
  agente/        # sistema multiagente LLM (loop ReAct, prompts)
dados/
  raw/           # datasets originais (CICIoT2023, N-BaIoT) — NÃO versionar
  processed/     # datasets tratados — NÃO versionar
experimentos/
  notebooks/     # exploração
  resultados/    # métricas, matrizes de confusão, logs de execução
referencias/     # bibliografia e material de apoio
reports/         # reports semanais para o orientador
ROADMAP.md       # ligação com o painel + histórico de mudanças do plano
```

Os PDFs de origem (`Artigo_TCC1.pdf`, `Poster_TCC1.pdf`, `EditalTCC_2026_2-V1.pdf`) e o feedback
integral do orientador (`PROFESSOR.md`) estão na pasta-mãe `RoadMap_TCC/`, fora deste repositório.

## Sincronização com o roadmap (obrigatório)

O painel de acompanhamento é o app em `../app/` (Node + Turso), usado pela equipe e pelo orientador.
As tarefas **não estão em arquivo** — vivem no banco Turso e são editadas pela interface do painel.

Por isso, **toda vez que o trabalho aqui alterar o plano**, registre em `ROADMAP.md`:

- uma tarefa concluída que valha marcar no painel;
- uma tarefa nova que apareceu, ou uma que deixou de fazer sentido;
- uma mudança de escopo (ex.: decidir não fazer captura in loco);
- uma mudança de prazo ou de ordem entre fases;
- um risco novo para o cronograma.

Cada entrada em `ROADMAP.md` diz **o que mudou, por quê, e o que fazer no painel**, e fica marcada
como `pendente` até alguém aplicar na interface — aí vira `aplicado`. Nunca alterar o banco Turso
por fora do app.

## Como trabalhar aqui

- Idioma: **português** no artigo, nos reports, nos commits e na conversa. Código e nomes de
  arquivo em inglês ou português sem acento, consistente com o que já existe.
- Nada de dataset, `.env`, credencial de Turso ou modelo treinado grande no git (ver `.gitignore`).
- Commits pequenos e descritivos, em português.
- Antes de escrever seção de artigo, conferir a lista de correções da banca acima.
- Ao terminar uma tarefa relevante, atualizar `ROADMAP.md` e o report da semana no mesmo passo.
