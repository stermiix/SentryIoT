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
features só distinguem os protocolos que têm indicador (HTTP, HTTPS, DNS, SSH, Telnet e poucos
outros), e o extrator lê arquivo pcap, não captura ao vivo. Mencionar a arquitetura híbrida (dado
da rede não sai do ambiente) como parte da contribuição.

## 1. Introdução

`[PENDENTE]` — enquadrar como NIDR (detecção **e** resposta), não NIDS, conforme reposicionamento
pedido pela banca do TCC I (ver `README.md`, seção "Correções da banca do TCC I").

## 2. Trabalhos correlatos

`[PENDENTE — texto]`. Fontes conferidas em 11/10/2026 (referências completas no fim):
- Neto et al. (2023) — artigo original do CICIoT2023 (revisado por pares, *Sensors*): agrupa as
  features em janelas de 10 e de 100 pacotes e calcula a média. Os pcaps e o código de extração
  dos autores vêm da página oficial do dataset (CANADIAN INSTITUTE FOR CYBERSECURITY, 2023).
- Doménech et al. (2025) — revisado por pares (*Internet of Things*, Elsevier). Confirmado: o
  artigo documenta a janela de 100 para DDoS, DoS e Mirai e de 10 para o resto, e mede queda de
  até 66,87% de F1 ao treinar num dataset e testar no outro. **Não confirmado** que recomende
  janela uniforme (ScienceDirect bloqueou a leitura): abrir o PDF pelo acesso da Mackenzie; se
  não houver recomendação explícita, escrever "documenta a diferença de janelas".
- Engelen, Rimmer e Joosen (2021) e Liu et al. (2022) — revisados por pares (IEEE SPW e IEEE
  CNS): erros de geração de tráfego, de features e de rótulo no CICIDS2017/CSE-CIC-IDS2018.
- Darktrace, Netskope, Vectra AI e *Denial of Wallet* (Kelly, Glavin e Barrett, 2021) — pedidos
  pela banca do TCC I, prioridade baixa, menção curta sem análise detalhada. Opcional: Zhang et
  al. (2026), *preprint* sobre *Denial of Wallet* em agentes LLM que chamam ferramentas.

Deixar explícito o que é contribuição nossa: o teste direto da janela trocada
(`experimentos/resultados/teste_da_janela.md`) e a medida de janelas sem pacote do atacante.

## 3. Metodologia

### 3.1 Captura e extração de features

O sistema processa tráfego bruto em arquivo PCAP, não apenas o CSV pré-processado do dataset —
resposta direta ao avaliador 2 do TCC I. A captura da rede é feita com Wireshark ou ferramenta
equivalente (a decidir); a extração das 39 features por janela de quadros é feita com `dpkt`, no
lugar do Scapy usado no TCC I. O Scapy fica restrito à captura de Zigbee e Bluetooth, fora do
escopo atual.

Os pcaps, os CSVs e o código de extração dos autores vêm da página oficial do CICIoT2023
(CANADIAN INSTITUTE FOR CYBERSECURITY, 2023). Todo o código e os scripts dos experimentos deste
trabalho estão disponíveis no repositório do projeto (OLIVEIRA et al., 2026).

O extrator (`codigo/captura/extrator.py`) foi calibrado contra os CSVs oficiais do CICIoT2023 em
5 pcaps (um por família: DDoS, DoS, Mirai, Recon e BruteForce), somando 167.304 linhas. As 39
colunas foram reproduzidas sem nenhuma divergência, com tolerância relativa de 1e-9 e desvio
relativo máximo observado de 9,88e-13 — atribuível a arredondamento de ponto flutuante
(`experimentos/resultados/calibracao.md`).

### 3.2 Pré-processamento e amostragem

Na fase exploratória, o `MERGED_CSV` publicado pelos autores (45.019.234 linhas, 63 arquivos) foi
amostrado com teto de 50.000 linhas por rótulo e semente fixa (42), preservando integralmente as
classes raras. A amostra resultante tem 1.288.479 linhas, registradas em
`experimentos/resultados/manifesto_amostra.json`. Os rótulos (34 classes) são normalizados e
mapeados para 7 categorias (DDoS e DoS fundidas, dado que suas features de pacote são
indistinguíveis — a separação dos dois é feita depois, pela quantidade de endereços de origem do
incidente, fora do modelo).

Os dados de treino finais, porém, não vêm do `MERGED_CSV`: são regerados a partir dos pcaps com o
nosso extrator (decisão de 2026-10-10, `ROADMAP.md`). O motivo está na seção 3.3 e nas limitações
do dataset: a janela de agregação varia com a classe e o rótulo é do arquivo inteiro. Na
regeração, cada um dos 38 pcaps (os 34 rótulos, três deles com uma segunda parte) é extraído em
janela única; numa captura benigna toda janela é benigna, e numa captura de ataque a janela só
recebe o rótulo do arquivo se contém um quadro de um dos sete Raspberry Pi atacantes
documentados pelos autores, e é descartada caso contrário. A divisão treino/teste é por tempo
dentro de cada pcap (os primeiros 70% das janelas para o treino) ou por arquivo inteiro quando o
rótulo tem mais de um pcap, o que evita que janelas vizinhas caiam dos dois lados. O teto de
50.000 janelas por rótulo e a semente 42 são mantidos (`codigo/classificador/regerar.py`,
`experimentos/resultados/regeracao.md`).

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
janela de 100 (`experimentos/resultados/teste_da_janela.md`). Retirar as seis colunas que
dependem do tamanho da janela não resolve. Foi esse resultado que levou à regeração dos dados
(seção 3.2).

Nos dados regerados, os dois modelos (janela de 10 e de 100) foram treinados e comparados, e a
janela de 100 quadros ficou como a do sistema (decisão de 2026-10-10). Com janela de 100:
macro-F1 de 82,3%, acurácia de 98,3%, DDoS+DoS com F1 de 99,3%, Mirai 99,6%, Spoofing 99,4%,
Recon 87,3%; Web (47,1%) e BruteForce (51,8%) continuam fracos, com recall entre 35% e 37%,
confundidos com Recon e com tráfego benigno. Num pcap benigno inteiro que o modelo não viu no
treino, 1,9% das janelas são classificadas como ataque, contra 12,7% com janela de 10; nos três
arquivos inteiros reservados para teste (`BenignTraffic2`, `DDoS-SYN_Flood1`, `DoS-SYN_Flood1`),
a acurácia é de 99,5%. A janela de 10 só supera a de 100 em Recon e Mirai, por menos de um ponto
(`experimentos/resultados/regeracao.md`). Ficam em aberto a proporção das classes no treino e o
limiar de operação para Web e BruteForce.

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

Arquitetura híbrida (decisão de 2026-10-10): os agentes de triagem e de execução, e a verificação
do efeito, rodam num modelo local (Ollama, no laboratório do grupo); só o agente de decisão pode
usar um modelo de fronteira pela nuvem, e recebe apenas o resumo da triagem, com endereços e
nomes de dispositivo trocados por rótulos neutros pelo orquestrador. O agente de execução, local,
desfaz a troca e é o único com credenciais. O orquestrador aceita três configurações, tudo local,
tudo na nuvem e híbrida, e a comparação entre elas em qualidade, custo e tempo é resultado do
artigo. Isso responde ao ponto da banca sobre riscos de IA em nuvem e à alternativa on-premises.

O classificador avisa a pessoa que opera a rede no instante em que o incidente abre, antes dos
agentes. A interface tem o botão "Já resolvido": com ele marcado, o agente de execução não aplica
remediação e o sistema só explica o incidente. O log grava o instante de cada etapa, da janela à
verificação, o que permite medir o tempo entre detecção e remediação, com e sem intervenção
humana.

## 4. Resultados

`[PENDENTE]` — consolidar aqui a versão final do classificador (os números da janela de 100 nos
dados regerados estão na seção 3.3; falta fechar a proporção das classes e rodar mais sementes) e,
quando disponíveis, as métricas dos agentes (qualidade da recomendação, custo em tokens, tempo
entre detecção e remediação) e a comparação entre as configurações local, nuvem e híbrida.

## 5. Limitações

Rascunho a partir do que já foi medido:
- **Atalho da janela no dataset oficial**: o modelo treinado no `MERGED_CSV` aprende o tamanho da
  janela, não o comportamento do tráfego (seção 3.3). A regeração em janela única resolve isso ao
  custo de treinar só com os pcaps disponíveis, e os resultados valem para a janela de 100.
- **Tráfego de fundo rotulado como ataque**: entre 33% e 87% das janelas de 10 dos pcaps de
  varredura, força bruta, Web e spoofing não contêm nenhum quadro do atacante
  (`experimentos/resultados/janelas_sem_atacante.md`); a regeração descarta essas janelas, e por
  isso Web e BruteForce ficam com poucas janelas de treino e de teste.
- **Web e BruteForce**: recall entre 35% e 37% nos dados regerados, confundidos com Recon e com
  tráfego benigno. Os pcaps dessas classes são curtos, e o grupo não tem captura própria.
- **Cenários da PoC**: DDoS, port scan e brute force. O cenário de exfiltração foi retirado com o
  orientador (decisão de 2026-10-10): o CICIoT2023 não tem essa classe, e os datasets de referência
  também não a cobrem com dados rotulados suficientes. O dataset secundário foi dispensado pelo
  mesmo motivo; o trabalho usa só o CICIoT2023.
- **Teste por arquivo inteiro**: só BenignTraffic, DDoS-SYN_Flood e DoS-SYN_Flood têm uma segunda
  captura reservada ao teste; nas demais classes a divisão é por tempo dentro do mesmo pcap, o
  que tende a superestimar o resultado.
- **Modelo local**: os agentes de triagem e execução rodam num modelo de 8 bilhões de parâmetros,
  mais fraco que o de fronteira; a comparação entre as configurações mede esse custo.

## 6. Conclusão

`[PENDENTE]` — escrever por último.

## Referências

Formato ABNT (NBR 6023). Itens marcados com `[CONFERIR]` ainda precisam de dado que não foi
possível confirmar por aqui.

CANADIAN INSTITUTE FOR CYBERSECURITY. **CIC IoT Dataset 2023**. Fredericton: University of New
Brunswick, 2023. Disponível em: https://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/. Acesso
em: 11 out. 2026.

DARKTRACE. **Darktrace leading the future of network detection and response with recognition
from KuppingerCole**. 2024. Disponível em:
https://www.darktrace.com/blog/darktrace-leading-the-future-of-network-detection-and-response-with-recognition-from-kuppingercole.
Acesso em: 11 out. 2026. `[CONFERIR ano na página]`

DOMÉNECH, J. et al. Evaluating and enhancing intrusion detection systems in IoMT: the importance
of domain-specific datasets. **Internet of Things**, 2025. Disponível em:
https://www.sciencedirect.com/science/article/pii/S2542660525001453. Acesso em: 11 out. 2026.
`[CONFERIR iniciais e lista de autores, volume e número do artigo]`

ENGELEN, G.; RIMMER, V.; JOOSEN, W. Troubleshooting an intrusion detection dataset: the
CICIDS2017 case study. In: IEEE SECURITY AND PRIVACY WORKSHOPS (SPW), 2021, San Francisco.
**Proceedings** [...]. [S. l.]: IEEE, 2021. p. 7-12. DOI: 10.1109/SPW53761.2021.00009.

KELLY, D.; GLAVIN, F. G.; BARRETT, E. **Denial of Wallet**: defining a looming threat to
serverless computing. arXiv, 2021. Disponível em: https://arxiv.org/abs/2104.08031. Acesso em:
11 out. 2026.

LIU, L.; ENGELEN, G.; LYNAR, T.; ESSAM, D.; JOOSEN, W. Error prevalence in NIDS datasets: a case
study on CIC-IDS-2017 and CSE-CIC-IDS-2018. In: IEEE CONFERENCE ON COMMUNICATIONS AND NETWORK
SECURITY (CNS), 2022, Austin. **Proceedings** [...]. [S. l.]: IEEE, 2022. p. 254-263. DOI:
10.1109/CNS56114.2022.9947235.

NETO, E. C. P.; DADKHAH, S.; FERREIRA, R.; ZOHOURIAN, A.; LU, R.; GHORBANI, A. A. CICIoT2023: a
real-time dataset and benchmark for large-scale attacks in IoT environment. **Sensors**, v. 23,
n. 13, 5941, 2023. DOI: 10.3390/s23135941.

NETSKOPE. **Netskope introduces SkopeAI**: revolutionary AI-driven security for the future of
data protection and cyber threat defense. 25 jul. 2023. Disponível em:
https://www.netskope.com/fr/press-releases/netskope-introduces-skopeai-revolutionary-ai-driven-security-for-the-future-of-data-protection-and-cyber-threat-defense.
Acesso em: 11 out. 2026.

OLIVEIRA, B. S.; GREGORIN, M. Q.; ROLING, J. V.; GUIMARÃES, P. H. C. **SentryIoT**: MultiAgent
NIDR. [S. l.]: GitHub, 2026. Repositório de código. Disponível em:
https://github.com/stermiix/SentryIoT. Acesso em: 11 out. 2026.

VECTRA AI. **Vectra advances security AI to deliver Attack Signal Intelligence**. Dark Reading,
12 out. 2022. Disponível em:
https://www.darkreading.com/operations/vectra-advances-security-ai-to-deliver-attack-signal-intelligence-empowering-security-teams-to-investigate-and-respond-to-attacks-in-real-time.
Acesso em: 11 out. 2026.

Opcional: ZHANG, J. et al. **Persistent billable state**: denial-of-wallet attacks and defenses
in tool-calling LLM agents. arXiv, 2026. Disponível em: https://arxiv.org/abs/2609.28585. Acesso
em: 11 out. 2026. `[CONFERIR autores]`
