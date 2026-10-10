# Esqueleto do artigo — SentryIoT (TCC II)

Rascunho das seções, para colar no template oficial do Oriente quando baixado. Trechos marcados
com `[PENDENTE]` ainda não têm conteúdo; os demais são rascunho pronto para revisão, a partir do
que já está decidido em `ROADMAP.md` e medido em `experimentos/resultados/`.

**Pendências fora do texto (ação humana, não dá para resolver por aqui):**
- Baixar o template oficial do artigo no Oriente e migrar este rascunho para ele.
- Confirmar com o orientador se o TCC II exige pôster e relatório além do artigo (edital cita os três).

---

## Resumo / Abstract

`[PENDENTE]` — escrever por último, depois que Resultados e Metodologia fecharem. Rever o que o
resumo do TCC I prometia (classificação em MQTT/CoAP e detecção em tempo real) e ajustar: as 39
features não distinguem protocolo de aplicação, e o extrator lê arquivo pcap, não captura ao vivo.

## 1. Introdução

`[PENDENTE]` — enquadrar como NIDR (detecção **e** resposta), não NIDS, conforme reposicionamento
pedido pela banca do TCC I (ver `README.md`, seção "Correções da banca do TCC I").

## 2. Trabalhos correlatos

`[PENDENTE — exige leitura das fontes antes de citar]`. Citar pelo menos:
- Neto et al. (2023) — artigo original do CICIoT2023, documenta as janelas de 10 e de 100 e o
  rótulo por arquivo.
- Doménech et al. (2025) — recomenda janela uniforme.
- Ramkumar et al. (2024) — regenerou os dados do CICIoT2023 filtrando por MAC do atacante.
- Engelen et al. (2021) e Liu et al. (2022) — correções equivalentes no CICIDS2017.
- Darktrace, Netskope, Vectra AI e o ataque *Denial of Wallet* — pedidos pela banca do TCC I,
  prioridade baixa, menção curta sem análise detalhada.

Deixar explícito o que é contribuição nossa: o teste direto da janela trocada
(`experimentos/resultados/teste_da_janela.md`) e a medida de janelas sem pacote do atacante.

## 3. Metodologia

### 3.1 Captura e extração de features

O sistema processa tráfego bruto em arquivo PCAP, não apenas o CSV pré-processado do dataset —
resposta direta ao avaliador 2 do TCC I. A captura da rede é feita com Wireshark ou ferramenta
equivalente (a decidir); a extração das 39 features por janela de quadros é feita com `dpkt`, no
lugar do Scapy usado no TCC I. O Scapy fica restrito à captura de Zigbee e Bluetooth, fora do
escopo atual.

O extrator (`codigo/captura/extrator.py`) foi calibrado contra os CSVs oficiais do CICIoT2023 em
5 pcaps (um por família: DDoS, DoS, Mirai, Recon e BruteForce), somando 167.304 linhas. As 39
colunas foram reproduzidas sem nenhuma divergência, com tolerância relativa de 1e-9 e desvio
relativo máximo observado de 9,88e-13 — atribuível a arredondamento de ponto flutuante
(`experimentos/resultados/calibracao.md`).

### 3.2 Pré-processamento e amostragem

O `MERGED_CSV` publicado pelos autores (45.019.234 linhas, 63 arquivos) foi amostrado com teto de
50.000 linhas por rótulo e semente fixa (42), preservando integralmente as classes raras. A
amostra resultante tem 1.288.479 linhas, registradas em `experimentos/resultados/manifesto_amostra.json`
para reprodutibilidade. Os rótulos (34 classes) são normalizados e mapeados para 7 categorias
(DDoS e DoS fundidas, dado que suas features de pacote são indistinguíveis — a separação dos dois
é feita depois, pela quantidade de endereços de origem do incidente, fora do modelo).

### 3.3 Treino e avaliação do classificador

O classificador é um Random Forest (scikit-learn, 100 árvores), treinado e avaliado sobre a
amostra descrita acima, com divisão de 80/20 entre treino e teste. Duas estratégias de divisão
foram testadas: sorteio estratificado de linhas (15,11% dos vetores de teste também aparecem no
treino, por causa de features repetidas) e divisão por grupos de vetores idênticos (0% de
sobreposição). Duas priores de treino também foram comparadas: a proporção da própria amostra e a
proporção natural do dataset completo (via peso de amostra).

Na melhor configuração testada (7 categorias, sorteio estratificado, priori da amostra, 39
features): acurácia de 93,81% na amostra de teste, equivalente a 98,58% quando reponderada para a
distribuição natural do dataset completo; macro-F1 de 74,11% (69,96% reponderado). Com a priori
natural, o alarme falso no tráfego benigno cai de 46,38% para 14,48%, mas o recall de Recon cai
de 92,61% para 76,83% e o de BruteForce despenca (`experimentos/resultados/treino_exploratorio.md`).

Um teste adicional, isolando o efeito do tamanho da janela, mostrou que o modelo treinado nas
janelas do `MERGED_CSV` (100 pacotes para DDoS/DoS/Mirai, 10 para as demais) não generaliza para
uma janela única na operação: o recall de floods HTTP cai a menos de 2% quando extraídos em
janela de 10, e o recall de varredura de portas e força bruta cai a 0–18% quando extraídos em
janela de 100 (`experimentos/resultados/teste_da_janela.md`). Essa decisão (janela única para
operação) segue em aberto — ver `ROADMAP.md`.

### 3.4 Justificativa do Random Forest

O modelo escolhido é o Random Forest, e não uma rede neural, por dois motivos: reproduz o
baseline já publicado pelos autores do dataset (Neto et al., 2023), que o situam entre os
melhores modelos testados; e, mais importante para o restante do sistema, permite recuperar quais
features pesaram em cada decisão de classificação. Essa explicabilidade é o insumo direto do
sistema multiagente: os agentes de decisão usam as features mais relevantes de um incidente para
compor a recomendação de mitigação. Uma rede neural entregaria apenas rótulo e confiança, sem essa
rastreabilidade por decisão.

### 3.5 Servidor MCP e sistema multiagente

`[PENDENTE — ligar à implementação real do servidor, hoje em stub]`. Resumo do contrato já fechado:
9 tools MCP divididas entre três agentes (triagem, decisão, execução); eventos registrados em log
JSONL; política de risco gradua ações em baixo risco (execução automática) e alto risco (aprovação
humana obrigatória), com teto de propostas pendentes por incidente para conter o custo de tokens
(ver `codigo/mcp/README.md` e `codigo/mcp/politica.toml`).

## 4. Resultados

`[PENDENTE]` — consolidar aqui a versão final do classificador (depois de resolvidas as decisões
em aberto de janela, priori e divisão treino/teste) e, quando disponíveis, as métricas dos agentes
(qualidade da recomendação, custo em tokens, latência) e da comparação isolado vs. integrado.

## 5. Limitações

Rascunho a partir do que já foi medido:
- **Atalho da janela**: o modelo depende do tamanho da janela de agregação; uma janela única na
  operação ainda não foi validada (seção 3.3).
- **Tráfego de fundo rotulado como ataque**: em medição preliminar, 62,5% das janelas de
  `Recon-PortScan.pcap` e 58,8% das de `DictionaryBruteForce.pcap` não contêm nenhum quadro do
  host atacante — a janela inteira herda o rótulo do ataque em curso mesmo quando só tem tráfego
  de outros dispositivos.
- **Quarto cenário da PoC (exfiltração)**: o CICIoT2023 não tem classe de exfiltração; decisão
  pendente com o orientador sobre substituir por um cenário baseado em acesso não autorizado ou
  incluir um dataset secundário com PCAP.

## 6. Conclusão

`[PENDENTE]` — escrever por último.

## Referências

`[PENDENTE]` — lista cresce conforme a seção 2 for escrita.
