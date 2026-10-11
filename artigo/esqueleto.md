# Esqueleto do artigo — SentryIoT (TCC II)

Rascunho das seções do artigo. Trechos marcados com `[PENDENTE]` ainda não têm conteúdo; os
demais são rascunho pronto para revisão, a partir do que já está decidido em `ROADMAP.md` e
medido em `experimentos/resultados/`.

**Pendências fora do texto (ação humana, não dá para resolver por aqui):**
- O texto do artigo está em `artigo/Artigo_TCC2_SentryIoT.docx`, no template do Oriente. Este
  esqueleto continua como rascunho e fonte das correções, que precisam ser levadas ao `.docx`.

Pelo edital, o TCC II de CC e SI entrega o artigo científico (10 a 20 páginas, submissão de 03 a
09/11/2026) e a apresentação oral (15 a 20 minutos). Relatório técnico e pôster são entregas do
TCC I.

---

## Resumo / Abstract

`[PENDENTE]` Escrever por último, depois que Resultados e Metodologia fecharem. Rever o que o
resumo do TCC I prometia (classificação em MQTT/CoAP e detecção em tempo real) e ajustar: as 39
features só distinguem os protocolos que têm indicador (HTTP, HTTPS, DNS, SSH, Telnet e poucos
outros), e o extrator lê arquivo pcap, não captura ao vivo. As demais diferenças em relação ao TCC
I estão na abertura da seção 3. Mencionar a arquitetura híbrida (dado da rede não sai do
ambiente) como parte da contribuição.

## 1. Introdução

`[PENDENTE]` Enquadrar como NIDR (detecção **e** resposta), não NIDS, conforme o
reposicionamento pedido pela banca do TCC I (ver `README.md`, seção "Correções da banca do TCC
I"). O título também precisa mudar: o do TCC I era "Detecção de Ataques em IoT com IA Preditiva
via MCP", e o do TCC II deve dizer detecção e resposta.

## 2. Trabalhos correlatos

`[PENDENTE: texto]`. Fontes conferidas em 11/10/2026 (referências completas no fim):
- Neto et al. (2023): artigo original do CICIoT2023, revisado por pares (*Sensors*), que agrupa
  as features em janelas de 10 e de 100 pacotes e calcula a média. Os pcaps e o código de extração
  dos autores vêm da página oficial do dataset (CANADIAN INSTITUTE FOR CYBERSECURITY, 2023).
- Doménech et al. (2025): revisado por pares (*Internet of Things*, Elsevier). Confirmado: o
  artigo documenta a janela de 100 para DDoS, DoS e Mirai e de 10 para o resto, e mede queda de
  até 66,87% de F1 ao treinar num dataset e testar no outro. **Não confirmado** que recomende
  janela uniforme (ScienceDirect bloqueou a leitura): abrir o PDF pelo acesso da Mackenzie; se
  não houver recomendação explícita, escrever "documenta a diferença de janelas".
- Engelen, Rimmer e Joosen (2021) e Liu et al. (2022): revisados por pares (IEEE SPW e IEEE
  CNS), sobre erros de geração de tráfego, de features e de rótulo no CICIDS2017/CSE-CIC-IDS2018.
- Darktrace, Netskope, Vectra AI e *Denial of Wallet* (Kelly, Glavin e Barrett, 2021): pedidos
  pela banca do TCC I, prioridade baixa, menção curta sem análise detalhada. Opcional: Zhang et
  al. (2026), *preprint* sobre *Denial of Wallet* em agentes LLM que chamam ferramentas.

Deixar explícito o que é contribuição nossa: a camada MCP, com o contrato das tools, a política
de risco graduada com aprovação humana e a arquitetura híbrida dos agentes, e a comparação entre
as configurações local, nuvem e híbrida; no classificador, o teste direto da janela trocada
(`experimentos/resultados/teste_da_janela.md`) e a medida, por pcap e por tamanho de janela, das
janelas sem quadro do atacante (`experimentos/resultados/janelas_sem_atacante.md`). A filtragem
por MAC do atacante já aparece em Ramkumar et al. (2024) e deve ser citada como tal
`[CONFERIR: Ramkumar et al. saiu da lista no #23; aguardando a equipe]`.

## 3. Metodologia

Em relação à proposta do TCC I, o trabalho mudou nos pontos a seguir. Não há classificação
específica de MQTT e CoAP, porque as 39 features só têm indicador para HTTP, HTTPS, DNS, SSH,
Telnet, SMTP, IRC e DHCP. A extração lê arquivo pcap, e a captura ao vivo fica como trabalho
futuro. Não houve busca de hiperparâmetros por grid search: o Random Forest usa os parâmetros
padrão do scikit-learn, porque a contribuição do trabalho está na camada MCP. O N-BaIoT deixou de
ser o dataset secundário, e nenhum outro o substituiu. O cenário de exfiltração de dados saiu da
PoC, porque o CICIoT2023 não tem essa classe. E os agentes rodam num modelo local, com modelos de
nuvem só nos experimentos, em vez de um único modelo comercial em nuvem.

### 3.1 Captura e extração de features

O sistema processa tráfego bruto em arquivo pcap, e não apenas o CSV pré-processado do dataset, o
que responde ao avaliador 2 do TCC I. A captura da rede grava um arquivo pcap, com `tcpdump`,
Wireshark ou ferramenta equivalente `[PENDENTE: fechar a ferramenta, decisão em aberto no
ROADMAP.md]`; a extração das 39 features por janela de quadros é feita com `dpkt`, como no código
dos autores do dataset, e não com o Scapy previsto no TCC I. No código dos autores, o Scapy só é
importado para Zigbee e Bluetooth e não contribui para nenhuma das 39 colunas.

Os pcaps, os CSVs e o código de extração dos autores vêm da página oficial do CICIoT2023
(CANADIAN INSTITUTE FOR CYBERSECURITY, 2023), e o código e os scripts dos experimentos deste
trabalho estão no repositório do projeto (OLIVEIRA et al., 2026). O trabalho não faz coleta in
loco em dispositivos IoT reais: seria inviável no prazo, e o tráfego capturado não teria rótulo.
O papel da captura é cumprido pelos pcaps brutos do CICIoT2023, que o extrator lê da mesma forma
que leria um arquivo gravado na rede. O Wireshark não é necessário ao sistema: serve para
inspecionar capturas, e a gravação pode ser feita com `tcpdump`. O Scapy também não é usado,
porque a extração precisa repetir o cálculo dos autores, feito com `dpkt`. A captura ao vivo fica
como um adaptador futuro sobre o mesmo extrator.

O extrator (`codigo/captura/extrator.py`) foi calibrado em duas etapas. Na primeira, contra os
CSVs oficiais de 5 pcaps, um por família (DDoS, DoS, Mirai, Recon e BruteForce), somando 167.304
linhas, as 39 colunas foram reproduzidas sem nenhuma divergência, com tolerância relativa de 1e-9;
o maior desvio relativo observado, de 9,88e-13, é da ordem do arredondamento de ponto flutuante
(`experimentos/resultados/calibracao.md`). Na segunda, os 38 pcaps foram extraídos como os autores
extraíram, em pedaços de 10 MB e com a janela da classe, e cada linha foi procurada entre as
linhas do mesmo rótulo no `MERGED_CSV` inteiro, com os 39 valores iguais até cerca de 9 algarismos
significativos. Em 15 rótulos, toda linha do `MERGED_CSV` tem par entre as nossas, o que não
aconteceria se o cálculo divergisse em alguma janela; do nosso lado, entre 95,53% e 99,00% das
linhas de cada pcap têm par, e o que falta vem dos arquivos do `MERGED_CSV` truncados na fonte
oficial (`experimentos/resultados/calibracao_conjunto.md`). Na regeração e na operação, o pcap é
lido de uma vez, sem o fatiamento de 10 MB; as distribuições das duas leituras são praticamente
iguais, com distância de Kolmogorov-Smirnov de no máximo 0,0102 entre as 39 colunas.

O sistema lê o pcap, e não registros NetFlow, outro ponto levantado pela banca do TCC I. Um
registro NetFlow típico resume cada fluxo em poucos campos: endereços, portas, protocolo,
quantidade de pacotes e de bytes, instantes de início e fim e, no máximo, a união das flags TCP
do fluxo. É leve e não guarda conteúdo, mas perde o que as 39 features do CICIoT2023 medem quadro
a quadro: a flag de cada pacote, o tamanho de cada quadro e a variação entre eles (`Min`, `Max`,
`Std`), o intervalo entre chegadas (`IAT`) e a fração da janela em cada protocolo de aplicação. O
custo do pcap é o volume, já que os 38 pcaps usados somam cerca de 46 GB, e a exposição do
conteúdo dos pacotes na captura; o extrator guarda só os campos de cabeçalho que mede e os
endereços da janela, e nenhum conteúdo de pacote chega aos agentes. Numa rede que só exporte
NetFlow, o classificador teria de ser treinado de novo, com outro conjunto de features.

### 3.2 Pré-processamento e amostragem

Na fase exploratória, o `MERGED_CSV` publicado pelos autores (45.019.234 linhas, 63 arquivos) foi
amostrado com teto de 50.000 linhas por rótulo e semente fixa (42), preservando integralmente as
classes raras. A amostra resultante tem 1.288.479 linhas, registradas em
`experimentos/resultados/manifesto_amostra.json`. Os rótulos (34 classes) são normalizados e
mapeados para 7 categorias, com DDoS e DoS juntos. As features descrevem os pacotes, e não
quantas máquinas atacam: 29,5% das linhas do `MERGED_CSV` têm o vetor das 39 features igual ao de
uma linha de outra categoria, quase sempre o mesmo flood rotulado como DDoS e como DoS. A
separação entre os dois é feita depois, pela quantidade de endereços de origem do incidente, fora
do modelo.

Os dados de treino finais, porém, não vêm do `MERGED_CSV`: são regerados a partir dos pcaps com o
nosso extrator (decisão de 2026-10-10, `ROADMAP.md`). O motivo está na seção 3.3 e nas limitações
do dataset: a janela de agregação varia com a classe e o rótulo é do arquivo inteiro. Na
regeração, cada um dos 38 pcaps é extraído em janela única. Os 34 rótulos têm pcap: 31 com um
arquivo, `DDoS-SYN_Flood` e `DoS-SYN_Flood` com dois cada e `BenignTraffic` com três. Numa captura
benigna toda janela é benigna, e numa captura de ataque a janela só recebe o rótulo do arquivo se
contém um quadro de um dos sete Raspberry Pi atacantes documentados pelos autores, e é descartada
caso contrário. A divisão treino/teste é por tempo dentro de cada pcap (os primeiros 70% das
janelas para o treino) ou por arquivo inteiro quando o rótulo tem mais de um pcap (o último, pelo
sufixo numérico do nome, fica no teste), o que evita que janelas vizinhas caiam dos dois lados. O teto de 50.000 janelas por rótulo e a semente 42 são
mantidos (`codigo/classificador/regerar.py`, `experimentos/resultados/regeracao.md`).

### 3.3 Treino e avaliação do classificador

As métricas do classificador são a precisão, o recall e o F1 de cada categoria, o macro-F1 e a
taxa de falso positivo, com destaque para o tráfego benigno classificado como ataque. A acurácia
global não é a métrica principal: DDoS e DoS somam 89,5% das linhas do `MERGED_CSV`, e um modelo
que respondesse DDoS para tudo acertaria 72,3%. `[PENDENTE: a equipe ainda não escolheu qual
medida do classificador do sistema é a principal no artigo: o corte por tempo, a rotação do pcap
benigno de fora do treino ou o pcap inteiro fora do treino. Até lá, o corte por tempo vem
primeiro, como no relatório da regeração, e os controles vêm em seguida, como resultados.]`

Na fase exploratória, o Random Forest (scikit-learn, 100 árvores, parâmetros padrão) foi treinado
e avaliado na amostra do `MERGED_CSV` descrita acima, com 80% das linhas para o treino e 20% para
o teste. Duas estratégias de divisão foram testadas: sorteio estratificado de linhas (15,11% dos
vetores de teste também aparecem no treino, por causa de features repetidas) e divisão por grupos
de vetores idênticos (0% de sobreposição). Duas priores de treino também foram comparadas: a
proporção da própria amostra e a proporção natural do dataset completo, por peso de amostra.

Na configuração tomada como referência (7 categorias, sorteio estratificado, priori da amostra,
39 features), a acurácia é de 93,81% na amostra de teste, ou 98,58% reponderada para a
distribuição natural do dataset completo, e o macro-F1 é de 74,11% (69,96% reponderado). A
divisão por grupos dá valores da mesma ordem, e a diferença entre as duas não se distingue do
ruído entre sementes. Com a priori natural, o tráfego benigno classificado como ataque cai de
46,38% para 14,48%, mas o recall reponderado de Recon cai de 92,52% para 78,87%, e o de
BruteForce, de 33,55% para 12,98% (`experimentos/resultados/treino_exploratorio.md`).

Um teste adicional, isolando o efeito do tamanho da janela, mostrou que o modelo treinado nas
janelas do `MERGED_CSV` (100 pacotes para DDoS/DoS/Mirai, 10 para as demais) não generaliza para
uma janela única na operação: o recall de floods HTTP cai a menos de 2% quando extraídos em
janela de 10, e o recall de varredura de portas e força bruta cai a 0–18% quando extraídos em
janela de 100 (`experimentos/resultados/teste_da_janela.md`). Retirar as seis colunas que
dependem do tamanho da janela não resolve. Foi esse resultado que levou à regeração dos dados
(seção 3.2).

O classificador do sistema é treinado de outra forma, nos dados regerados (seção 3.2): um Random
Forest de 100 árvores, com os parâmetros padrão do scikit-learn e sem busca de hiperparâmetros,
nas 39 features, em 7 categorias, com janela de 100 quadros, teto de 50.000 janelas por rótulo,
semente 42 e a divisão por tempo e por arquivo descrita na seção 3.2. São 567.732 janelas de
treino e 273.566 de teste (`experimentos/resultados/regeracao.md`).

Nos dados regerados, os dois modelos (janela de 10 e de 100) foram treinados e comparados, e a
janela de 100 quadros ficou como a do sistema (decisão de 2026-10-10). Com janela de 100, no corte
por tempo: macro-F1 de 82,3%, acurácia de 98,3%, DDoS+DoS com F1 de 99,3%, Mirai 99,6%, Spoofing
99,4%, Recon 87,3%; Web (47,1%) e BruteForce (51,8%) continuam fracos, com recall entre 35% e 37%,
confundidos com Recon e com tráfego benigno. Nos três arquivos inteiros reservados para teste
(`BenignTraffic2`, `DDoS-SYN_Flood1` e `DoS-SYN_Flood1`), que só têm tráfego benigno e floods de
SYN, a acurácia é de 99,5%, e 1,9% das janelas benignas são classificadas como ataque, contra
12,7% com janela de 10. A janela de 10 só tem recall maior em Recon e Mirai, por menos de um
ponto, e F1 maior só em Mirai (`experimentos/resultados/regeracao.md`).

O corte por tempo mede o reconhecimento de um trecho seguinte da mesma captura. Os controles a
seguir medem o que ele não mostra (`experimentos/resultados/rodadas_de_teste.md`). Entre cinco
sementes, o macro-F1 vai de 82,09% a 82,29%, e o tráfego benigno classificado como ataque, de
1,60% a 1,86%. Com cada um dos três pcaps benignos fora do treino, um por vez, a fração
classificada como ataque vai de 1,5% (`BenignTraffic1.pcap`) a 38,5% (`BenignTraffic.pcap`, em que
32% das janelas viram Recon), e é de 15,4% somando os três: o 1,9% acima é o de uma das rotações.
Com o pcap inteiro fora do treino, o recall de Recon cai de 87,7% para 31,5% e o de Web, de 37,1%
para 31,3%; BruteForce tem um pcap só, e sem ele a categoria some do treino. As janelas de fundo
dos pcaps de ataque, sem nenhum quadro do atacante, viram ataque em 72% dos casos na parte de
teste. Como janelas vizinhas erram juntas, os intervalos de 95% foram calculados por blocos de
janelas vizinhas: vão de 31,1% a 43,1% no recall de Web e de 19,2% a 52,0% no de BruteForce.

O Spoofing de 99,4% depende da captura. 84% das janelas de Spoofing têm quadro menor que 60 bytes,
gravado sem o preenchimento do Ethernet, o que nas demais categorias quase não acontece, e o fundo
dos dois pcaps de spoofing, sem quadro do atacante, cai na categoria Spoofing em 97,7% e 99,5% das
janelas. Com o quadro medido como no fio, o recall de Spoofing cai para 88,2% no corte por tempo e
para 66% com o pcap fora do treino (`experimentos/resultados/rodadas_normalizadas.md`). Ficam em
aberto o tratamento do tráfego de fundo no treino e o ponto de operação, por limiar sobre a
probabilidade de benigno e por janelas seguidas, a escolher numa parte de validação (`ROADMAP.md`,
decisões em aberto).

### 3.4 Justificativa do Random Forest

O modelo escolhido é o Random Forest, e não uma rede neural, por dois motivos: no benchmark
publicado pelos autores do dataset (Neto et al., 2023), ele está entre os melhores modelos
testados; e, mais importante para o restante do sistema, a importância de cada feature sai do
próprio treino, sem um método de explicação à parte. Neste trabalho, a importância é medida por
redução média de impureza e vale para o modelo inteiro (`experimentos/resultados/regeracao.md`).
Para cada incidente, o servidor entrega aos agentes as features principais, com o valor de
referência do tráfego benigno, e é esse o insumo da recomendação de mitigação. `[PENDENTE: dizer
como as features principais de um incidente são escolhidas; se for adotada atribuição por
decisão, como o TreeSHAP, citar o método.]` O protocolo dos autores não é reproduzido aqui: o
notebook publicado não treina o Random Forest, e os nossos dados de treino são regerados dos
pcaps, então os números não se comparam diretamente com os do artigo do dataset.

### 3.5 Servidor MCP e sistema multiagente

`[PENDENTE: ligar à implementação real do servidor, hoje em stub]` O contrato, na versão 0.3.0,
tem 10 tools MCP divididas entre os três agentes (triagem, decisão e execução) e grava cada passo
num log de eventos em JSONL. O incidente traz a categoria do modelo, que junta DDoS e DoS
(`DDoS+DoS`), e a categoria depois da regra que separa os dois pela quantidade de origens. A
política de risco separa as ações de risco baixo, aplicadas sem aprovação, das de risco alto, que
dependem de aprovação humana, e limita a 10 as propostas que aguardam aprovação em cada incidente,
porque a fila é lida por uma pessoa e um agente enganado por conteúdo vindo da rede poderia
enchê-la. Como a origem de um flood UDP ou ICMP pode ser forjada, bloquear uma origem da rede
local é de risco alto, os endereços críticos (o servidor MCP, o host do modelo local e o
resolvedor DNS) são protegidos, e o teto de medidas de risco baixo ativas vale por incidente (5) e
para o sistema todo (10). O custo de tokens é contido de outra forma: os agentes recebem o resumo
do incidente, e não as janelas, e o detalhe vem em fatias de até 20 janelas. Na PoC, a resposta é
executada num ambiente simulado, com aprovação humana e possibilidade de desfazer (ver
`codigo/mcp/README.md` e `codigo/mcp/politica.toml`).

Arquitetura híbrida (decisões de 2026-10-10 e 2026-10-11): os agentes de triagem e de execução,
e a verificação do efeito, rodam num modelo local, o Qwen3 8B servido pelo Ollama num computador
do laboratório (GPU RTX 2070 Super); só o agente de decisão pode usar um modelo de fronteira pela
nuvem, acessado pelo OpenRouter. A garantia de que nenhum endereço da rede chega a ele está no
servidor, e não no prompt: o agente de decisão não tem as tools que devolvem endereços e lê o
incidente por `obter_resumo`, montado pelo servidor com um rótulo neutro (`origem-1`,
`destino-1`) no lugar de cada endereço. Ele propõe a ação com o rótulo; o servidor troca o rótulo
pelo endereço e calcula o risco sobre o endereço real, e só o agente de execução, local e o único
com credenciais, recebe o endereço. Toda resposta à linha de decisão passa ainda por um filtro
que troca por um marcador qualquer endereço que tenha sobrado em texto livre. O veredito da
triagem, texto livre escrito pelo modelo local, precisa passar pelo mesmo filtro antes de chegar
ao agente de decisão `[a implementar no orquestrador]`. O orquestrador aceitará três
configurações, tudo local, tudo na nuvem e híbrida, e a comparação entre elas em qualidade, custo
e tempo é resultado do artigo. Isso responde ao ponto da banca sobre riscos de IA em nuvem e à
alternativa on-premises.

A busca na internet dos agentes fica desligada por padrão, e por isso nenhum dado da rede sai da
máquina por ela; a comparação com a busca ligada fica como experimento. O custo em tokens é
medido por chamada: cada chamada ao modelo grava no log o agente, o modelo e os tokens de entrada
e de saída, e o contador da interface mostra quantas chamadas um incidente gerou. O risco de
Denial of Wallet será tratado pela política de acionamento `[a escrever]`, no orquestrador, que
agrupará os alertas do mesmo ataque e fará de um flood de centenas de janelas por segundo um único
incidente, e não centenas de chamadas ao modelo. Hoje não há teto de incidentes enviados ao
modelo da nuvem, e origens forjadas podem abrir vários incidentes: esse teto também cabe à
política de acionamento.

A pessoa que opera a rede será avisada no instante em que o incidente abrir, antes dos agentes
`[a implementar no modo ao vivo da interface]`, e pode marcar o incidente como já resolvido. A
marca é o evento `incidente_marcado_resolvido`, gravado hoje pelo comando de aprovação
(`aprovar --resolvido`) e, mais adiante, pelo botão "Já resolvido" da interface, com o canal e o
usuário. Daí em diante o servidor recusa qualquer proposta do incidente e a execução das propostas
dele, inclusive as já aprovadas, e o comando de aprovação recusa aprovar as pendentes; o que já
estava aplicado pode ser desfeito, e o agente de decisão, que vê a marca no resumo, só explica o
incidente. O log grava o instante de cada etapa, da janela à verificação, o que permite medir o
tempo entre detecção e remediação, com e sem intervenção humana. Do lado da detecção, a janela de
100 quadros fecha, na mediana, em 5 ms em DDoS e DoS e entre 1,3 s e 2,5 s em Recon, BruteForce e
Web, e a classificação de uma janela leva 1,6 ms (`experimentos/resultados/rodadas_de_teste.md`).

### 3.6 Avaliação da PoC e dos agentes

`[PENDENTE]` Cenários: DDoS, varredura de portas e força bruta, reproduzidos a partir dos pcaps
do CICIoT2023. Comparações: a saída isolada do classificador contra a saída integrada, com os
agentes, no mesmo incidente, como previa o TCC I; e as três configurações dos agentes (tudo
local, tudo na nuvem e híbrida). Medidas: qualidade da recomendação `[métrica a definir]`; tokens
e custo por incidente; tempo entre a abertura do incidente e a remediação, com e sem a marca de já
resolvido; e propostas aprovadas, rejeitadas e desfeitas. Segurança do MCP: o teste de tool
poisoning `[a escrever]`.

## 4. Resultados

`[PENDENTE]` Consolidar aqui a versão final do classificador (os números da janela de 100 nos
dados regerados e os controles estão na seção 3.3; falta escolher a medida principal, o
tratamento do tráfego de fundo e o ponto de operação) e, quando disponíveis, as métricas dos agentes (qualidade da recomendação, custo em tokens, tempo
entre detecção e remediação) e a comparação entre as configurações local, nuvem e híbrida.

## 5. Limitações

Rascunho a partir do que já foi medido:
- **Atalho da janela no dataset oficial**: o modelo treinado no `MERGED_CSV` aprende o tamanho da
  janela, não o comportamento do tráfego (seção 3.3). A regeração em janela única resolve isso ao
  custo de treinar só com os pcaps disponíveis, e os resultados valem para a janela de 100.
- **Tráfego de fundo**: entre 33% e 87% das janelas de 10 dos pcaps de varredura, força bruta,
  Web e spoofing não contêm nenhum quadro do atacante
  (`experimentos/resultados/janelas_sem_atacante.md`). A regeração descarta essas janelas, e por
  isso Web e BruteForce ficam com poucas janelas de treino e de teste. Classificadas pelo modelo,
  72% delas viram ataque, e nos pcaps de spoofing e no `VulnerabilityScan.pcap` a maior parte cai
  na categoria da própria captura. Parte do fundo pode conter efeito do ataque, e por isso essa
  fração é uma estimativa pessimista do alarme falso durante um ataque.
- **Web e BruteForce**: recall entre 35% e 37% no corte por tempo, confundidos com Recon e com
  tráfego benigno, e com intervalos largos: por blocos, de 19,2% a 52,0% em BruteForce, que tem
  um tamanho efetivo de 15 janelas de teste. Os pcaps dessas classes são curtos, e o grupo não tem
  captura própria.
- **Outra captura da mesma categoria**: com o pcap inteiro fora do treino, o recall de Recon cai
  de 87,7% para 31,5% (5,8% no `VulnerabilityScan.pcap`), o de Mirai, de 99,2% para 55,3% (0% no
  `Mirai-udpplain.pcap`), e o de Web, de 37,1% para 31,3%. Cada pcap de Recon e de Web é uma
  técnica diferente, e tirar o pcap tira também a técnica do treino. BruteForce tem um pcap só.
- **Alarme falso conforme o pcap benigno**: com cada pcap benigno fora do treino, a fração
  classificada como ataque vai de 1,5% a 38,5%.
- **Artefato de captura**: os pcaps não foram gravados todos do mesmo jeito. 84% das janelas de
  Spoofing têm quadro menor que 60 bytes, sem o preenchimento do Ethernet, e 88% das janelas
  benignas têm quadro maior que 1.514 bytes, que só existe com segmentação feita pela placa da
  máquina que capturou; numa rede real, os tamanhos seriam outros. O TTL também pesa: é a feature
  que mais derruba o recall do tráfego benigno quando permutada, e as janelas benignas com TTL
  médio até 64 viram ataque em 9,3% dos casos, contra 1,4% acima de 90. Medir o quadro como no
  fio foi testado e não adotado, porque piora as medidas com o pcap fora do treino sem melhorar o
  alarme falso (seção 3.3).
- **Cenários da PoC**: DDoS, port scan e brute force. O cenário de exfiltração foi retirado com o
  orientador (decisão de 2026-10-10): o CICIoT2023 não tem essa classe, e os datasets de referência
  também não a cobrem com dados rotulados suficientes. O dataset secundário foi dispensado pelo
  mesmo motivo; o trabalho usa só o CICIoT2023.
- **Teste por arquivo inteiro**: só BenignTraffic, DDoS-SYN_Flood e DoS-SYN_Flood têm mais de um
  arquivo, e o último fica inteiro no teste. Os sete arquivos desses rótulos estão entre os 20
  pcaps com cerca de 2.048.000.000 bytes, o tamanho em que o `tcpdump -C 2048` corta o arquivo:
  são partes da mesma gravação, e não capturas independentes
  (`experimentos/resultados/calibracao_conjunto.md`). Nas demais classes a divisão é por tempo
  dentro do mesmo pcap, o que tende a superestimar o resultado.
- **Separação entre DDoS e DoS**: por janela, as faixas de IPs de origem das duas categorias se
  cruzam, e a contagem inclui os IPs da vítima e do tráfego de fundo
  (`experimentos/resultados/regeracao.md`); a regra no nível do incidente ainda não foi medida.
- **O atacante também gera tráfego comum**: 27,1% das janelas de 100 dos pcaps benignos têm ao
  menos um quadro de um MAC atacante, e entram no treino como benignas.
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
