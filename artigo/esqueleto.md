# Esqueleto do artigo — SentryIoT (TCC II)

Rascunho das seções, para colar no template oficial do Oriente quando baixado. Trechos marcados
com `[PENDENTE]` ainda não têm conteúdo; os demais são rascunho pronto para revisão, a partir do
que já está decidido em `ROADMAP.md` e medido em `experimentos/resultados/`.

**Pendências fora do texto (ação humana, não dá para resolver por aqui):**
- Baixar o template oficial do artigo no Oriente e migrar este rascunho para ele.

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

`[PENDENTE — exige leitura das fontes antes de citar]`. Citar pelo menos:
- Neto et al. (2023) — artigo original do CICIoT2023, documenta as janelas de 10 e de 100 e o
  rótulo por arquivo.
- Doménech et al. (2025) — recomenda janela uniforme.
- Ramkumar et al. (2024) — regenerou os dados do CICIoT2023 filtrando por MAC do atacante.
- Engelen et al. (2021) e Liu et al. (2022) — correções equivalentes no CICIDS2017.
- Darktrace, Netskope, Vectra AI e o ataque *Denial of Wallet* — pedidos pela banca do TCC I,
  prioridade baixa, menção curta sem análise detalhada.

Deixar explícito o que é contribuição nossa: a camada MCP, com o contrato das tools, a política
de risco graduada com aprovação humana e a arquitetura híbrida dos agentes, e a comparação entre
as configurações local, nuvem e híbrida; no classificador, o teste direto da janela trocada
(`experimentos/resultados/teste_da_janela.md`) e a medida, por pcap e por tamanho de janela, das
janelas sem quadro do atacante (`experimentos/resultados/janelas_sem_atacante.md`). A filtragem
por MAC do atacante já aparece em Ramkumar et al. (2024) e deve ser citada como tal.

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

O trabalho não faz coleta in loco em dispositivos IoT reais: seria inviável no prazo, e o tráfego
capturado não teria rótulo. O papel da captura é cumprido pelos pcaps brutos do CICIoT2023, que o
extrator lê da mesma forma que leria um arquivo gravado na rede. O Wireshark não é necessário ao
sistema: serve para inspecionar capturas, e a gravação pode ser feita com `tcpdump`. O Scapy
também não é usado, porque a extração precisa repetir o cálculo dos autores, feito com `dpkt`. A
captura ao vivo fica como um adaptador futuro sobre o mesmo extrator.

O extrator (`codigo/captura/extrator.py`) foi calibrado contra os CSVs oficiais do CICIoT2023 em
5 pcaps (um por família: DDoS, DoS, Mirai, Recon e BruteForce), somando 167.304 linhas. As 39
colunas foram reproduzidas sem nenhuma divergência, com tolerância relativa de 1e-9 e desvio
relativo máximo observado de 9,88e-13 — atribuível a arredondamento de ponto flutuante
(`experimentos/resultados/calibracao.md`).

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
janelas para o treino) ou por arquivo inteiro quando o rótulo tem mais de um pcap, o que evita que
janelas vizinhas caiam dos dois lados. O teto de 50.000 janelas por rótulo e a semente 42 são
mantidos (`codigo/classificador/regerar.py`, `experimentos/resultados/regeracao.md`).

### 3.3 Treino e avaliação do classificador

As métricas do classificador são a precisão, o recall e o F1 de cada categoria, o macro-F1 e a
taxa de falso positivo, com destaque para o tráfego benigno classificado como ataque. A acurácia
global não é a métrica principal: DDoS e DoS somam 89,5% das linhas do `MERGED_CSV`, e um modelo
que respondesse DDoS para tudo acertaria 72,3%.

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
janela de 100 quadros ficou como a do sistema (decisão de 2026-10-10). Com janela de 100:
macro-F1 de 82,3%, acurácia de 98,3%, DDoS+DoS com F1 de 99,3%, Mirai 99,6%, Spoofing 99,4%,
Recon 87,3%; Web (47,1%) e BruteForce (51,8%) continuam fracos, com recall entre 35% e 37%,
confundidos com Recon e com tráfego benigno. Num pcap benigno inteiro que o modelo não viu no
treino, 1,9% das janelas são classificadas como ataque, contra 12,7% com janela de 10; nos três
arquivos inteiros reservados para teste (`BenignTraffic2`, `DDoS-SYN_Flood1` e `DoS-SYN_Flood1`),
que só têm tráfego benigno e floods de SYN, a acurácia é de 99,5%. A janela de 10 só tem recall
maior em Recon e Mirai, por menos de um ponto, e F1 maior só em Mirai
(`experimentos/resultados/regeracao.md`). Ficam em aberto a proporção das classes no treino e o
limiar de operação para Web e BruteForce.

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

`[PENDENTE: ligar à implementação real do servidor, hoje em stub]` O contrato tem 9 tools MCP
divididas entre os três agentes (triagem, decisão e execução) e grava cada passo num log de
eventos em JSONL. A política de risco separa as ações de risco baixo, aplicadas sem aprovação,
das de risco alto, que dependem de aprovação humana, e limita a 10 as propostas que aguardam
aprovação em cada incidente, porque a fila é lida por uma pessoa e um agente enganado por
conteúdo vindo da rede poderia enchê-la. O custo de tokens é contido de outra forma: os agentes
recebem o resumo do incidente, e não as janelas, e o detalhe vem em fatias de até 20 janelas. Na
PoC, a resposta é executada num ambiente simulado, com aprovação humana e possibilidade de
desfazer (ver `codigo/mcp/README.md` e `codigo/mcp/politica.toml`).

Arquitetura híbrida (decisão de 2026-10-10): os agentes de triagem e de execução, e a verificação
do efeito, rodam num modelo local, o Qwen3 8B servido pelo Ollama num computador do laboratório
(GPU RTX 2070 Super); só o agente de decisão pode usar um modelo de fronteira pela nuvem, acessado
pelo OpenRouter, e recebe apenas o resumo da triagem, com endereços e nomes de dispositivo
trocados por rótulos neutros pelo orquestrador. O agente de execução, local, desfaz a troca e é o
único com credenciais. O orquestrador aceita três configurações, tudo local, tudo na nuvem e
híbrida, e a comparação entre elas em qualidade, custo e tempo é resultado do artigo. Isso
responde ao ponto da banca sobre riscos de IA em nuvem e à alternativa on-premises.

A busca na internet dos agentes fica desligada por padrão, e por isso nenhum dado da rede sai da
máquina por ela; a comparação com a busca ligada fica como experimento. O custo em tokens é
medido por chamada: cada chamada ao modelo grava no log o agente, o modelo e os tokens de entrada
e de saída, e o contador da interface mostra quantas chamadas um incidente gerou. O risco de
Denial of Wallet será tratado pela política de acionamento `[a escrever]`, que fará de um flood
de centenas de janelas por segundo um único incidente, e não centenas de chamadas ao modelo.

O classificador avisa a pessoa que opera a rede no instante em que o incidente abre, antes dos
agentes. A interface tem o botão "Já resolvido": com ele marcado, o agente de execução não aplica
remediação e o sistema só explica o incidente. O log grava o instante de cada etapa, da janela à
verificação, o que permite medir o tempo entre detecção e remediação, com e sem intervenção
humana.

### 3.6 Avaliação da PoC e dos agentes

`[PENDENTE]` Cenários: DDoS, varredura de portas e força bruta, reproduzidos a partir dos pcaps
do CICIoT2023. Comparações: a saída isolada do classificador contra a saída integrada, com os
agentes, no mesmo incidente, como previa o TCC I; e as três configurações dos agentes (tudo
local, tudo na nuvem e híbrida). Medidas: qualidade da recomendação `[métrica a definir]`; tokens
e custo por incidente; tempo entre a abertura do incidente e a remediação, com e sem a marca de já
resolvido; e propostas aprovadas, rejeitadas e desfeitas. Segurança do MCP: o teste de tool
poisoning `[a escrever]`.

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

`[PENDENTE]` — lista cresce conforme a seção 2 for escrita.
