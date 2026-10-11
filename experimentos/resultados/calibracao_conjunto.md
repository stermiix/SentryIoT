# Calibração de conjunto do extrator

Gerado por `python -m codigo.captura.calibrar_conjunto` em 11/10/2026, com Python 3.11.2, dpkt 1.9.8, numpy 2.4.6 e pandas 3.0.6.

O `calibracao.md` compara o extrator com o CSV oficial de cada pcap, linha a linha, e cobre os 5 pcaps
que tinham esse CSV na máquina. Os CSVs por ataque não estão mais na cópia do dataset. O que existe é o
`MERGED_CSV`, que junta as linhas de todas as capturas dos autores, embaralhadas e sem o nome do arquivo
de origem. Esta calibração confere todos os pcaps da pasta do dataset contra ele: as linhas de cada pcap,
extraídas como os autores extraíram, são procuradas entre as linhas do mesmo rótulo no `MERGED_CSV`.

## Resumo

- 38 pcaps, 34 rótulos, contra as 45.019.234 linhas dos 63 arquivos do `MERGED_CSV`.
- Em 15 rótulos os nossos pcaps cobrem todas as linhas do `MERGED_CSV`: cada linha desses rótulos tem par entre as nossas, e uma divergência do extrator em qualquer janela deles deixaria essa cobertura abaixo de 100%. É a prova de que o cálculo é o dos autores. Do nosso lado, o `MERGED_CSV` traz 95,77% das nossas linhas nesses rótulos; o que falta é a perda dos arquivos truncados na fonte oficial.
- Em todos os pcaps, entre 95,53% e 99,00% das nossas linhas têm par entre as linhas do mesmo rótulo: uma linha do `MERGED_CSV` com os 39 valores iguais aos nossos até cerca de 9 algarismos significativos. Nas linhas únicas (uma vez no pcap e no máximo uma no `MERGED_CSV`), entre 95,53% e 96,33%. Nenhum pedaço de 10 MB fica com menos da metade das linhas com par.
- No total, os pcaps cobrem 5.297.358 das 45.019.234 linhas do `MERGED_CSV` (11,77%).
- Instante: 38 pcaps em microssegundos. Nenhum quadro IPv4 ou ARP ficou de fora da extração.

## O que foi conferido

1. O índice do `MERGED_CSV`: cada um dos arquivos é lido sozinho, com a linha final incompleta dos
   arquivos truncados descartada (9 arquivos: `Merged42.csv`, `Merged44.csv`, `Merged46.csv`, `Merged47.csv`, `Merged48.csv`, `Merged49.csv`, `Merged50.csv`, `Merged51.csv`, `Merged52.csv`), e o rótulo de cada linha é normalizado para a
   grafia canônica. Por rótulo, guardam-se os hashes das linhas.
2. A chave de cada linha arredonda os 39 valores a 30 bits de mantissa (erro
   relativo de até cerca de 4,7e-10, perto de 9 algarismos), deixa o infinito como está, põe todo NaN num
   padrão só e mistura os valores num hash de 64 bits. O `MERGED_CSV` escreve os números no formato do
   Java (`3.861904144287109E-5`), o infinito como texto e o NaN como campo vazio, então a chave é sobre o
   valor numérico, e não sobre o texto. Também não é uma comparação bit a bit: o `MERGED_CSV` grava o `IAT`
   com 15 algarismos significativos (`0.0417121887207031`, contra `0.041712188720703126` no extrator), e
   `Rate`, `Std` e `Variance` às vezes diferem no último bit, de um jeito de somar ou de imprimir para
   outro. Em quatro rótulos pequenos conferidos à parte, o maior desvio relativo entre valores que casam
   foi de 9,5e-13, muito abaixo do arredondamento da chave. Par, aqui, quer dizer os 39 valores iguais
   até cerca de 9 algarismos significativos.
3. A extração de cada pcap é a dos autores: pedaços de 10.000.000 de bytes, como o `tcpdump -C 10`
   (`calibrar.fatiar`), um extrator novo por pedaço e a janela da classe, 100 em DDoS, DoS e Mirai e 10
   nas demais. Na mesma leitura sai a extração contínua, a da operação e da regeração dos dados de treino.
4. (a) Fração das nossas linhas com par no rótulo do pcap, por multiconjunto: cada linha do `MERGED_CSV`
   serve de par a uma linha nossa só. (b) Fração das linhas de cada rótulo no `MERGED_CSV` cobertas pelos
   pcaps daquele rótulo. Para as linhas sem par, o que o `MERGED_CSV` do rótulo tem de igual a elas: a
   mesma linha, uma linha igual fora as colunas de tempo (`Rate`, `IAT`) ou fora as de tamanho. E em que
   outro rótulo as linhas do pcap mais aparecem.
5. Controle do vizinho mais próximo: até 200 linhas sem par de cada pcap, sorteadas
   entre as que nenhuma dessas igualdades explica, comparadas coluna a coluna com a linha mais parecida do
   mesmo rótulo no `MERGED_CSV`, procurada entre todas as que têm a mesma chave grossa.
6. Leitura contínua contra fatiada, em todos os pcaps.

## Resultado por pcap

Colunas completas em `calibracao_conjunto_pcaps.csv`. A última coluna é o rótulo em que as linhas do pcap
mais aparecem fora do próprio, pela simples presença da linha.

| pcap | rótulo | janela | pacotes | quadros IPv4 e ARP | pedaços de 10 MB | nossas linhas | com par no MERGED | (a) fração | (b) cobertura do rótulo | maior fração em outro rótulo |
|---|---|---|---|---|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | Backdoor_Malware | 10 | 33.414 | 32.178 | 2 | 3.218 | 3.078 | 95,65% | 100,00% | < 1% |
| `BenignTraffic.pcap` | BenignTraffic | 10 | 3.664.164 | 3.622.775 | 205 | 362.361 | 346.917 | 95,74% | 88,18% | < 1% |
| `BenignTraffic1.pcap` | BenignTraffic | 10 | 2.988.642 | 2.954.889 | 205 | 295.585 | 283.079 | 95,77% | 88,18% | < 1% |
| `BenignTraffic2.pcap` | BenignTraffic | 10 | 3.138.002 | 3.103.184 | 205 | 310.413 | 297.207 | 95,75% | 88,18% | < 1% |
| `BrowserHijacking.pcap` | BrowserHijacking | 10 | 59.821 | 58.571 | 4 | 5.859 | 5.630 | 96,09% | 100,00% | MITM-ArpSpoofing (2,44%) |
| `CommandInjection.pcap` | CommandInjection | 10 | 55.741 | 54.083 | 3 | 5.409 | 5.168 | 95,54% | 100,00% | < 1% |
| `DDoS-ACK_Fragmentation.pcap` | DDoS-ACK_Fragmentation | 100 | 2.503.835 | 2.498.356 | 205 | 25.090 | 24.011 | 95,70% | 8,80% | < 1% |
| `DDoS-HTTP_Flood-.pcap` | DDoS-HTTP_Flood | 100 | 2.881.005 | 2.875.590 | 62 | 28.790 | 27.597 | 95,86% | 100,00% | < 1% |
| `DDoS-ICMP_Flood.pcap` | DDoS-ICMP_Flood | 100 | 26.793.240 | 26.790.856 | 205 | 268.010 | 265.196 | 98,95% | 3,85% | < 1% |
| `DDoS-ICMP_Fragmentation.pcap` | DDoS-ICMP_Fragmentation | 100 | 2.064.692 | 2.059.666 | 205 | 20.696 | 19.779 | 95,57% | 4,57% | < 1% |
| `DDoS-PSHACK_Flood.pcap` | DDoS-PSHACK_Flood | 100 | 26.774.357 | 26.771.116 | 205 | 267.811 | 264.393 | 98,72% | 6,74% | < 1% |
| `DDoS-RSTFINFlood.pcap` | DDoS-RSTFINFlood | 100 | 26.686.473 | 26.683.145 | 205 | 266.934 | 262.876 | 98,48% | 6,79% | < 1% |
| `DDoS-SYN_Flood.pcap` | DDoS-SYN_Flood | 100 | 26.597.011 | 26.592.439 | 205 | 266.024 | 260.771 | 98,03% | 13,45% | DDoS-SynonymousIP_Flood (49,52%) |
| `DDoS-SYN_Flood1.pcap` | DDoS-SYN_Flood | 100 | 26.715.334 | 26.709.607 | 205 | 267.197 | 262.163 | 98,12% | 13,45% | DDoS-SynonymousIP_Flood (52,89%) |
| `DDoS-SlowLoris.pcap` | DDoS-SlowLoris | 100 | 2.351.454 | 2.339.029 | 68 | 23.426 | 22.400 | 95,62% | 100,00% | < 1% |
| `DDoS-SynonymousIP_Flood.pcap` | DDoS-SynonymousIP_Flood | 100 | 26.855.630 | 26.852.421 | 205 | 268.626 | 265.929 | 99,00% | 7,72% | DDoS-SYN_Flood (72,73%) |
| `DDoS-TCP_Flood.pcap` | DDoS-TCP_Flood | 100 | 26.570.958 | 26.567.030 | 205 | 265.776 | 262.916 | 98,92% | 6,11% | DoS-TCP_Flood (71,10%) |
| `DDoS-UDP_Flood.pcap` | DDoS-UDP_Flood | 100 | 26.653.551 | 26.650.250 | 205 | 266.605 | 263.287 | 98,76% | 5,08% | DoS-UDP_Flood (64,91%) |
| `DDoS-UDP_Fragmentation.pcap` | DDoS-UDP_Fragmentation | 100 | 2.248.843 | 2.243.805 | 205 | 22.542 | 21.659 | 96,08% | 7,88% | < 1% |
| `DNS_Spoofing.pcap` | DNS_Spoofing | 10 | 1.812.557 | 1.788.712 | 75 | 178.898 | 171.468 | 95,85% | 100,00% | < 1% |
| `DictionaryBruteForce.pcap` | DictionaryBruteForce | 10 | 133.138 | 130.632 | 4 | 13.064 | 12.522 | 95,85% | 100,00% | < 1% |
| `DoS-HTTP_Flood1.pcap` | DoS-HTTP_Flood | 100 | 3.114.983 | 3.109.872 | 150 | 31.175 | 29.833 | 95,70% | 43,36% | < 1% |
| `DoS-SYN_Flood.pcap` | DoS-SYN_Flood | 100 | 26.261.611 | 26.258.588 | 205 | 262.691 | 253.752 | 96,60% | 26,40% | DDoS-SYN_Flood (21,36%) |
| `DoS-SYN_Flood1.pcap` | DoS-SYN_Flood | 100 | 26.405.653 | 26.402.526 | 205 | 264.126 | 259.161 | 98,12% | 26,40% | DDoS-SYN_Flood (58,54%) |
| `DoS-TCP_Flood.pcap` | DoS-TCP_Flood | 100 | 26.005.549 | 26.002.745 | 205 | 260.129 | 255.862 | 98,36% | 10,00% | DDoS-TCP_Flood (64,32%) |
| `DoS-UDP_Flood.pcap` | DoS-UDP_Flood | 100 | 16.676.370 | 16.673.777 | 205 | 166.838 | 163.476 | 97,98% | 5,15% | DDoS-UDP_Flood (38,04%) |
| `MITM-ArpSpoofing.pcap` | MITM-ArpSpoofing | 10 | 2.491.622 | 2.476.451 | 143 | 247.706 | 237.717 | 95,97% | 80,73% | BenignTraffic (5,69%) |
| `Mirai-greeth_flood.pcap` | Mirai-greeth_flood | 100 | 3.352.569 | 3.350.061 | 205 | 33.597 | 32.278 | 96,07% | 3,40% | < 1% |
| `Mirai-greip_flood21.pcap` | Mirai-greip_flood | 100 | 1.196.296 | 1.195.447 | 71 | 11.991 | 11.510 | 95,99% | 1,60% | < 1% |
| `Mirai-udpplain.pcap` | Mirai-udpplain | 100 | 3.642.269 | 3.638.873 | 205 | 36.481 | 35.041 | 96,05% | 4,11% | < 1% |
| `Recon-HostDiscovery.pcap` | Recon-HostDiscovery | 10 | 1.371.112 | 1.343.683 | 23 | 134.378 | 128.677 | 95,76% | 100,00% | < 1% |
| `Recon-OSScan.pcap` | Recon-OSScan | 10 | 992.241 | 982.430 | 33 | 98.259 | 93.970 | 95,64% | 100,00% | Recon-PortScan (2,57%) |
| `Recon-PingSweep.pcap` | Recon-PingSweep | 10 | 22.943 | 22.619 | 1 | 2.262 | 2.161 | 95,53% | 100,00% | < 1% |
| `Recon-PortScan.pcap` | Recon-PortScan | 10 | 831.856 | 822.771 | 21 | 82.284 | 78.730 | 95,68% | 100,00% | Recon-OSScan (3,28%) |
| `SqlInjection.pcap` | SqlInjection | 10 | 53.462 | 52.441 | 1 | 5.245 | 5.022 | 95,75% | 100,00% | < 1% |
| `Uploading_Attack.pcap` | Uploading_Attack | 10 | 12.939 | 12.513 | 1 | 1.252 | 1.196 | 95,53% | 100,00% | < 1% |
| `VulnerabilityScan.pcap` | VulnerabilityScan | 10 | 3.802.533 | 3.733.119 | 103 | 373.351 | 357.583 | 95,78% | 100,00% | < 1% |
| `XSS.pcap` | XSS | 10 | 40.183 | 38.446 | 2 | 3.846 | 3.705 | 96,33% | 100,00% | < 1% |

## Cobertura por rótulo

Tabela também em `calibracao_conjunto_rotulos.csv`.

| rótulo | pcaps | linhas no MERGED_CSV | nossas linhas | linhas do MERGED cobertas | (b) cobertura |
|---|---|---|---|---|---|
| Backdoor_Malware | 1 | 3.078 | 3.218 | 3.078 | 100,00% |
| BenignTraffic | 3 | 1.051.373 | 968.359 | 927.074 | 88,18% |
| BrowserHijacking | 1 | 5.630 | 5.859 | 5.630 | 100,00% |
| CommandInjection | 1 | 5.168 | 5.409 | 5.168 | 100,00% |
| DDoS-ACK_Fragmentation | 1 | 272.793 | 25.090 | 24.011 | 8,80% |
| DDoS-HTTP_Flood | 1 | 27.597 | 28.790 | 27.597 | 100,00% |
| DDoS-ICMP_Flood | 1 | 6.893.259 | 268.010 | 265.196 | 3,85% |
| DDoS-ICMP_Fragmentation | 1 | 433.157 | 20.696 | 19.779 | 4,57% |
| DDoS-PSHACK_Flood | 1 | 3.920.372 | 267.811 | 264.393 | 6,74% |
| DDoS-RSTFINFlood | 1 | 3.872.808 | 266.934 | 262.876 | 6,79% |
| DDoS-SYN_Flood | 2 | 3.886.130 | 533.221 | 522.818 | 13,45% |
| DDoS-SlowLoris | 1 | 22.400 | 23.426 | 22.400 | 100,00% |
| DDoS-SynonymousIP_Flood | 1 | 3.445.659 | 268.626 | 265.929 | 7,72% |
| DDoS-TCP_Flood | 1 | 4.306.086 | 265.776 | 262.916 | 6,11% |
| DDoS-UDP_Flood | 1 | 5.181.027 | 266.605 | 263.287 | 5,08% |
| DDoS-UDP_Fragmentation | 1 | 274.909 | 22.542 | 21.659 | 7,88% |
| DNS_Spoofing | 1 | 171.468 | 178.898 | 171.468 | 100,00% |
| DictionaryBruteForce | 1 | 12.522 | 13.064 | 12.522 | 100,00% |
| DoS-HTTP_Flood | 1 | 68.799 | 31.175 | 29.833 | 43,36% |
| DoS-SYN_Flood | 2 | 1.942.176 | 526.817 | 512.796 | 26,40% |
| DoS-TCP_Flood | 1 | 2.558.256 | 260.129 | 255.862 | 10,00% |
| DoS-UDP_Flood | 1 | 3.177.323 | 166.838 | 163.476 | 5,15% |
| MITM-ArpSpoofing | 1 | 294.469 | 247.706 | 237.717 | 80,73% |
| Mirai-greeth_flood | 1 | 949.381 | 33.597 | 32.278 | 3,40% |
| Mirai-greip_flood | 1 | 719.655 | 11.991 | 11.510 | 1,60% |
| Mirai-udpplain | 1 | 852.695 | 36.481 | 35.041 | 4,11% |
| Recon-HostDiscovery | 1 | 128.677 | 134.378 | 128.677 | 100,00% |
| Recon-OSScan | 1 | 93.970 | 98.259 | 93.970 | 100,00% |
| Recon-PingSweep | 1 | 2.161 | 2.262 | 2.161 | 100,00% |
| Recon-PortScan | 1 | 78.730 | 82.284 | 78.730 | 100,00% |
| SqlInjection | 1 | 5.022 | 5.245 | 5.022 | 100,00% |
| Uploading_Attack | 1 | 1.196 | 1.252 | 1.196 | 100,00% |
| VulnerabilityScan | 1 | 357.583 | 373.351 | 357.583 | 100,00% |
| XSS | 1 | 3.705 | 3.846 | 3.705 | 100,00% |

## Como ler os números

- **A prova de que o cálculo é o dos autores é a cobertura (b) de 100% nos 15 rótulos completos.** Neles, toda linha do `MERGED_CSV` tem par entre as nossas. Uma divergência do extrator ou
  da emulação do fatiamento em qualquer janela desses rótulos deixaria uma linha deles sem par, e (b)
  abaixo de 100%. A fração (a), sozinha, não basta: uma divergência numa coluna ou num protocolo raro
  moveria (a) em décimos de ponto, dentro da perda dos arquivos truncados.
- **A cobertura (b) baixa nos floods e no benigno não indica erro.** O `MERGED_CSV` vem de todas as
  capturas dos autores, e temos uma ou duas partes de cada rótulo. 20 dos 38 pcaps têm entre 2.048.000.000 e
  2.048.100.000 bytes, o que indica partes cortadas com `tcpdump -C 2048` de capturas maiores. Nesses
  rótulos a cobertura mede quanto do rótulo temos, e não a qualidade do extrator. O que mede o extrator
  é a fração (a).
- **O que falta nos rótulos completos vem dos arquivos truncados.** Nos rótulos em que os nossos pcaps
  cobrem todas as linhas do `MERGED_CSV`, ele traz 95,77% das nossas linhas
  (entre 95,53% e 96,33% por pcap). Os arquivos truncados na fonte oficial perderam as linhas
  que viriam depois do corte, e como o conjunto é embaralhado a perda cai em todas as classes em
  proporção parecida: o `exploracao.md` mede 4,26% de linhas a menos contra os CSVs por ataque.
- **Acima dessa faixa, o excesso vem das linhas repetidas dos floods** (12 pcaps). Uma linha nossa que se
  perdeu no `MERGED_CSV` ainda acha par numa linha idêntica vinda de outra parte da mesma captura. Nas
  linhas únicas, que não têm essa ajuda, (a) fica entre 95,53% e 96,33% em todos os pcaps.
- **A fração em outro rótulo** mostra a sobreposição já conhecida entre DDoS e DoS (`ROADMAP.md`,
  04/10/2026): as mesmas janelas aparecem com os dois rótulos.

## Leitura contínua contra leitura fatiada

A operação e a regeração dos dados de treino leem o pcap de uma vez; o `MERGED_CSV` vem da leitura em
pedaços de 10 MB. A diferença sistemática é uma janela incompleta e um IAT zerado por pedaço. Depois da
primeira fronteira de pedaço as janelas ficam deslocadas, e as linhas deixam de coincidir uma a uma, mas
as distribuições ficam praticamente iguais. A última coluna é a maior distância de Kolmogorov-Smirnov
entre as duas leituras, entre as 39 colunas.

| pcap | janela | linhas fatiada | linhas contínua | incompletas fatiada / contínua | fatiada no MERGED | contínua no MERGED | contínua igual à fatiada | maior KS |
|---|---|---|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | 10 | 3.218 | 3.218 | 1 / 1 | 95,65% | 95,62% | 99,97% | `IAT` 0,0003 |
| `BenignTraffic.pcap` | 10 | 362.361 | 362.278 | 180 / 1 | 95,74% | 10,19% | 10,44% | `Tot sum` 0,0014 |
| `BenignTraffic1.pcap` | 10 | 295.585 | 295.489 | 194 / 1 | 95,77% | 8,30% | 8,42% | `IAT` 0,0012 |
| `BenignTraffic2.pcap` | 10 | 310.413 | 310.319 | 192 / 1 | 95,75% | 14,05% | 14,52% | `ack_count` 0,0014 |
| `BrowserHijacking.pcap` | 10 | 5.859 | 5.858 | 4 / 1 | 96,09% | 29,63% | 30,76% | `Std` 0,0093 |
| `CommandInjection.pcap` | 10 | 5.409 | 5.409 | 2 / 1 | 95,54% | 54,82% | 57,20% | `Std` 0,0063 |
| `DDoS-ACK_Fragmentation.pcap` | 100 | 25.090 | 24.984 | 201 / 1 | 95,70% | 1,95% | 1,52% | `Number` 0,0080 |
| `DDoS-HTTP_Flood-.pcap` | 100 | 28.790 | 28.756 | 61 / 1 | 95,86% | 1,80% | 1,87% | `syn_count` 0,0050 |
| `DDoS-ICMP_Flood.pcap` | 100 | 268.010 | 267.909 | 200 / 1 | 98,95% | 75,89% | 50,08% | `Rate` 0,0014 |
| `DDoS-ICMP_Fragmentation.pcap` | 100 | 20.696 | 20.597 | 203 / 1 | 95,57% | 2,35% | 2,45% | `Number` 0,0098 |
| `DDoS-PSHACK_Flood.pcap` | 100 | 267.811 | 267.712 | 203 / 1 | 98,72% | 70,42% | 48,45% | `IAT` 0,0012 |
| `DDoS-RSTFINFlood.pcap` | 100 | 266.934 | 266.832 | 203 / 1 | 98,48% | 65,74% | 44,08% | `IAT` 0,0016 |
| `DDoS-SYN_Flood.pcap` | 100 | 266.024 | 265.925 | 205 / 1 | 98,03% | 53,96% | 35,44% | `Rate` 0,0016 |
| `DDoS-SYN_Flood1.pcap` | 100 | 267.197 | 267.097 | 203 / 1 | 98,12% | 57,15% | 37,94% | `IAT` 0,0009 |
| `DDoS-SlowLoris.pcap` | 100 | 23.426 | 23.391 | 68 / 1 | 95,62% | 1,94% | 2,03% | `psh_flag_number` 0,0072 |
| `DDoS-SynonymousIP_Flood.pcap` | 100 | 268.626 | 268.525 | 203 / 1 | 99,00% | 77,20% | 55,04% | `Rate` 0,0014 |
| `DDoS-TCP_Flood.pcap` | 100 | 265.776 | 265.671 | 204 / 1 | 98,92% | 75,30% | 55,18% | `IAT` 0,0011 |
| `DDoS-UDP_Flood.pcap` | 100 | 266.605 | 266.503 | 203 / 1 | 98,76% | 71,57% | 51,34% | `Rate` 0,0018 |
| `DDoS-UDP_Fragmentation.pcap` | 100 | 22.542 | 22.439 | 202 / 1 | 96,08% | 2,35% | 1,53% | `Tot sum` 0,0102 |
| `DNS_Spoofing.pcap` | 10 | 178.898 | 178.872 | 63 / 1 | 95,85% | 18,22% | 18,99% | `Time_To_Live` 0,0015 |
| `DictionaryBruteForce.pcap` | 10 | 13.064 | 13.064 | 3 / 1 | 95,85% | 27,96% | 29,17% | `Tot sum` 0,0086 |
| `DoS-HTTP_Flood1.pcap` | 100 | 31.175 | 31.099 | 149 / 1 | 95,70% | 4,79% | 4,91% | `Number` 0,0047 |
| `DoS-SYN_Flood.pcap` | 100 | 262.691 | 262.586 | 203 / 1 | 96,60% | 23,56% | 14,58% | `Rate` 0,0022 |
| `DoS-SYN_Flood1.pcap` | 100 | 264.126 | 264.026 | 203 / 1 | 98,12% | 58,13% | 42,62% | `Rate` 0,0014 |
| `DoS-TCP_Flood.pcap` | 100 | 260.129 | 260.028 | 204 / 1 | 98,36% | 63,75% | 50,76% | `Rate` 0,0016 |
| `DoS-UDP_Flood.pcap` | 100 | 166.838 | 166.738 | 204 / 1 | 97,98% | 55,40% | 34,08% | `Rate` 0,0021 |
| `MITM-ArpSpoofing.pcap` | 10 | 247.706 | 247.646 | 126 / 1 | 95,97% | 20,97% | 21,38% | `Std` 0,0016 |
| `Mirai-greeth_flood.pcap` | 100 | 33.597 | 33.501 | 202 / 1 | 96,07% | 11,94% | 2,99% | `Tot sum` 0,0066 |
| `Mirai-greip_flood21.pcap` | 100 | 11.991 | 11.955 | 71 / 1 | 95,99% | 8,67% | 1,72% | `Tot sum` 0,0077 |
| `Mirai-udpplain.pcap` | 100 | 36.481 | 36.389 | 202 / 1 | 96,05% | 9,28% | 2,14% | `Tot sum` 0,0064 |
| `Recon-HostDiscovery.pcap` | 10 | 134.378 | 134.369 | 20 / 1 | 95,76% | 9,37% | 9,77% | `Std` 0,0019 |
| `Recon-OSScan.pcap` | 10 | 98.259 | 98.243 | 30 / 0 | 95,64% | 12,22% | 12,76% | `Rate` 0,0023 |
| `Recon-PingSweep.pcap` | 10 | 2.262 | 2.262 | 1 / 1 | 95,53% | 95,53% | 100,00% | 0 |
| `Recon-PortScan.pcap` | 10 | 82.284 | 82.278 | 17 / 1 | 95,68% | 12,86% | 13,36% | `Time_To_Live` 0,0019 |
| `SqlInjection.pcap` | 10 | 5.245 | 5.245 | 1 / 1 | 95,75% | 95,75% | 100,00% | 0 |
| `Uploading_Attack.pcap` | 10 | 1.252 | 1.252 | 1 / 1 | 95,53% | 95,53% | 100,00% | 0 |
| `VulnerabilityScan.pcap` | 10 | 373.351 | 373.312 | 91 / 1 | 95,78% | 15,36% | 16,03% | `Rate` 0,0010 |
| `XSS.pcap` | 10 | 3.846 | 3.845 | 2 / 1 | 96,33% | 70,40% | 73,13% | `IAT` 0,0074 |

Maior distância entre todos os pcaps e colunas: 0,0102.

## Linhas sem par

São 150.225 linhas sem par nos 38 pcaps. Para cada uma, o índice diz o que o `MERGED_CSV` do rótulo tem de igual a ela, na ordem da tabela: a primeira classe que se aplica é a da linha.

| o que o `MERGED_CSV` tem | linhas sem par | fração |
|---|---|---|
| a mesma linha, que já serviu de par a outra linha nossa igual | 2.141 | 1,43% |
| uma linha igual fora `Rate` e `IAT` | 73.047 | 48,63% |
| uma linha igual fora as colunas de tamanho | 49 | 0,03% |
| nada disso | 74.988 | 49,92% |

A primeira classe vem da correspondência por multiconjunto: cada linha do `MERGED_CSV` serve de par a uma linha nossa só, e uma linha que se repete mais no pcap do que lá fica com a sobra sem par. A segunda é comum em tráfego repetitivo, em que muitas janelas têm os mesmos quadros e só os instantes mudam; ela não separa uma janela que falta no `MERGED_CSV` de uma calculada com outro instante, e por isso não prova nada sozinha.

### O vizinho mais próximo das linhas da última classe

Foram examinadas 7.007 linhas da última classe, até 200 por pcap. Para cada uma, o `MERGED_CSV` foi percorrido e todas as linhas do mesmo rótulo com o mesmo `Number` e os mesmos tamanhos, ou com o mesmo protocolo e as mesmas contagens de flags, foram comparadas com ela, sem limite de candidatas, pelos valores arredondados da chave. O vizinho é a que difere em menos colunas.

| desfecho | linhas |
|---|---|
| o vizinho difere em `Rate` ou `IAT` e em outras colunas | 6.540 |
| o vizinho difere só em outras colunas | 14 |
| nenhuma linha com a mesma chave grossa | 453 |

Colunas que diferem no vizinho mais próximo, por quantidade de linhas:

| colunas diferentes | linhas |
|---|---|
| 2 | 8 |
| 3 | 968 |
| 4 | 257 |
| 5 | 333 |
| 6 | 394 |
| 7 | 640 |
| 8 | 995 |
| 9 | 1.046 |
| 10 | 756 |
| 11 | 418 |
| 12 | 261 |
| 13 | 146 |
| 14 | 79 |
| 15 | 69 |
| 16 | 53 |
| 17 | 41 |
| 18 | 31 |
| 19 | 21 |
| 20 | 12 |
| 21 | 9 |
| 22 | 8 |
| 23 | 7 |
| 24 | 2 |

O que a tabela mostra: das 7.007 linhas, 6.554 têm vizinho, que difere delas em 8 colunas na mediana, e 453 não têm nenhuma linha com a mesma chave grossa. As colunas que mais diferem são `Rate` (6.535), `IAT` (6.531), `Time_To_Live` (5.232), `Std` (4.576), `Variance` (4.576), `Tot sum` (3.807), `AVG` (3.807), `Tot size` (3.807). O vizinho só ilustra o que falta no `MERGED_CSV`; a prova de que as linhas sem par não vêm de um cálculo diferente é a cobertura (b) de 100% nos rótulos completos. Por pcap, os desfechos estão no manifesto, em `vizinho`.

## A captura de cada pcap

O que o cabeçalho e os quadros de cada pcap dizem da captura. O instante em nanossegundos seria truncado
para microssegundos, como o `tcpdump -r ... -w` do fatiamento dos autores grava. Quadro menor que 60
bytes não passa assim no fio (falta o preenchimento) e quadro maior que 1514 bytes só existe com
offload de segmentação na máquina que capturou. As opções `--preencher` e `--limitar` do extrator
medem o quadro como no fio. Nesta calibração, que reproduz os autores, ficaram `--preencher` e `--limitar` desligadas.

- Quadro menor que 60 bytes: `DNS_Spoofing.pcap`, `MITM-ArpSpoofing.pcap`, `Mirai-greip_flood21.pcap`. Quadro maior que 1514 bytes: 35 dos 38 pcaps.
- Limite de captura declarado: 262.144 bytes em 35 pcaps; 1.500 bytes em 3 pcaps.
- Nenhum pcap tem registro gravado com menos bytes que o quadro original (limite de captura curto).

| pcap | instante | limite de captura | gravados menores que o original | quadros < 60 B | quadros > 1514 B | quadros fora do filtro |
|---|---|---|---|---|---|---|
| `Backdoor_Malware.pcap` | microssegundos | 262.144 | 0 | 0 | 392 | IPv6: 601; IEEE 802.3 com LLC (STP e afins): 545; teste de enlace (loopback): 90 |
| `BenignTraffic.pcap` | microssegundos | 262.144 | 0 | 0 | 215.864 | IEEE 802.3 com LLC (STP e afins): 19.628; IPv6: 18.428; teste de enlace (loopback): 3.333 |
| `BenignTraffic1.pcap` | microssegundos | 262.144 | 0 | 0 | 222.992 | IPv6: 15.789; IEEE 802.3 com LLC (STP e afins): 15.355; teste de enlace (loopback): 2.609 |
| `BenignTraffic2.pcap` | microssegundos | 262.144 | 0 | 0 | 202.265 | IEEE 802.3 com LLC (STP e afins): 17.005; IPv6: 14.921; teste de enlace (loopback): 2.892 |
| `BrowserHijacking.pcap` | microssegundos | 262.144 | 0 | 0 | 3.887 | IPv6: 615; IEEE 802.3 com LLC (STP e afins): 545; teste de enlace (loopback): 90 |
| `CommandInjection.pcap` | microssegundos | 262.144 | 0 | 0 | 467 | IPv6: 852; IEEE 802.3 com LLC (STP e afins): 692; teste de enlace (loopback): 114 |
| `DDoS-ACK_Fragmentation.pcap` | microssegundos | 262.144 | 0 | 0 | 2.132 | IEEE 802.3 com LLC (STP e afins): 3.357; IPv6: 1.904; teste de enlace (loopback): 218 |
| `DDoS-HTTP_Flood-.pcap` | microssegundos | 262.144 | 0 | 0 | 20.094 | IPv6: 4.138; IEEE 802.3 com LLC (STP e afins): 1.171; teste de enlace (loopback): 106 |
| `DDoS-ICMP_Flood.pcap` | microssegundos | 262.144 | 0 | 0 | 1.033 | IEEE 802.3 com LLC (STP e afins): 1.604; IPv6: 641; teste de enlace (loopback): 139 |
| `DDoS-ICMP_Fragmentation.pcap` | microssegundos | 262.144 | 0 | 0 | 1.643 | IEEE 802.3 com LLC (STP e afins): 3.521; IPv6: 1.296; teste de enlace (loopback): 209 |
| `DDoS-PSHACK_Flood.pcap` | microssegundos | 262.144 | 0 | 0 | 1.525 | IEEE 802.3 com LLC (STP e afins): 2.007; IPv6: 1.092; teste de enlace (loopback): 142 |
| `DDoS-RSTFINFlood.pcap` | microssegundos | 262.144 | 0 | 0 | 2.128 | IPv6: 1.700; IEEE 802.3 com LLC (STP e afins): 1.485; teste de enlace (loopback): 143 |
| `DDoS-SYN_Flood.pcap` | microssegundos | 262.144 | 0 | 0 | 2.703 | IEEE 802.3 com LLC (STP e afins): 2.941; IPv6: 1.387; teste de enlace (loopback): 244 |
| `DDoS-SYN_Flood1.pcap` | microssegundos | 262.144 | 0 | 0 | 1.693 | IEEE 802.3 com LLC (STP e afins): 3.915; IPv6: 1.585; teste de enlace (loopback): 227 |
| `DDoS-SlowLoris.pcap` | microssegundos | 262.144 | 0 | 0 | 46.909 | IPv6: 6.494; IEEE 802.3 com LLC (STP e afins): 5.073; teste de enlace (loopback): 858 |
| `DDoS-SynonymousIP_Flood.pcap` | microssegundos | 262.144 | 0 | 0 | 795 | IEEE 802.3 com LLC (STP e afins): 2.493; IPv6: 578; teste de enlace (loopback): 138 |
| `DDoS-TCP_Flood.pcap` | microssegundos | 262.144 | 0 | 0 | 3.763 | IEEE 802.3 com LLC (STP e afins): 2.543; IPv6: 1.196; teste de enlace (loopback): 189 |
| `DDoS-UDP_Flood.pcap` | microssegundos | 262.144 | 0 | 0 | 2.879 | IEEE 802.3 com LLC (STP e afins): 2.230; IPv6: 884; teste de enlace (loopback): 187 |
| `DDoS-UDP_Fragmentation.pcap` | microssegundos | 262.144 | 0 | 0 | 1.722 | IEEE 802.3 com LLC (STP e afins): 2.670; IPv6: 2.157; teste de enlace (loopback): 211 |
| `DNS_Spoofing.pcap` | microssegundos | 1.500 | 0 | 305.469 | 0 | IPv6: 11.920; IEEE 802.3 com LLC (STP e afins): 10.245; teste de enlace (loopback): 1.680 |
| `DictionaryBruteForce.pcap` | microssegundos | 262.144 | 0 | 0 | 2.917 | IEEE 802.3 com LLC (STP e afins): 1.236; IPv6: 1.066; teste de enlace (loopback): 204 |
| `DoS-HTTP_Flood1.pcap` | microssegundos | 262.144 | 0 | 0 | 171.975 | IEEE 802.3 com LLC (STP e afins): 2.531; IPv6: 2.188; teste de enlace (loopback): 392 |
| `DoS-SYN_Flood.pcap` | microssegundos | 262.144 | 0 | 0 | 7.044 | IPv6: 1.478; IEEE 802.3 com LLC (STP e afins): 1.341; teste de enlace (loopback): 204 |
| `DoS-SYN_Flood1.pcap` | microssegundos | 262.144 | 0 | 0 | 3.149 | IEEE 802.3 com LLC (STP e afins): 1.692; IPv6: 1.238; teste de enlace (loopback): 197 |
| `DoS-TCP_Flood.pcap` | microssegundos | 262.144 | 0 | 0 | 6.056 | IEEE 802.3 com LLC (STP e afins): 1.418; IPv6: 1.181; teste de enlace (loopback): 205 |
| `DoS-UDP_Flood.pcap` | microssegundos | 262.144 | 0 | 0 | 4.068 | IEEE 802.3 com LLC (STP e afins): 1.292; IPv6: 1.136; teste de enlace (loopback): 165 |
| `MITM-ArpSpoofing.pcap` | microssegundos | 1.500 | 0 | 196.508 | 0 | IEEE 802.3 com LLC (STP e afins): 7.956; IPv6: 5.906; teste de enlace (loopback): 1.309 |
| `Mirai-greeth_flood.pcap` | microssegundos | 262.144 | 0 | 0 | 13.597 | IPv6: 1.277; IEEE 802.3 com LLC (STP e afins): 1.146; teste de enlace (loopback): 85 |
| `Mirai-greip_flood21.pcap` | microssegundos | 1.500 | 0 | 1.419 | 0 | IEEE 802.3 com LLC (STP e afins): 703; IPv6: 113; teste de enlace (loopback): 33 |
| `Mirai-udpplain.pcap` | microssegundos | 262.144 | 0 | 0 | 1.386 | IEEE 802.3 com LLC (STP e afins): 1.718; IPv6: 1.537; teste de enlace (loopback): 141 |
| `Recon-HostDiscovery.pcap` | microssegundos | 262.144 | 0 | 0 | 20.335 | IPv6: 13.006; IEEE 802.3 com LLC (STP e afins): 12.393; teste de enlace (loopback): 2.030 |
| `Recon-OSScan.pcap` | microssegundos | 262.144 | 0 | 0 | 26.179 | IEEE 802.3 com LLC (STP e afins): 4.915; IPv6: 4.086; teste de enlace (loopback): 810 |
| `Recon-PingSweep.pcap` | microssegundos | 262.144 | 0 | 0 | 574 | IPv6: 155; IEEE 802.3 com LLC (STP e afins): 145; teste de enlace (loopback): 24 |
| `Recon-PortScan.pcap` | microssegundos | 262.144 | 0 | 0 | 17.789 | IEEE 802.3 com LLC (STP e afins): 4.438; IPv6: 3.915; teste de enlace (loopback): 732 |
| `SqlInjection.pcap` | microssegundos | 262.144 | 0 | 0 | 616 | IEEE 802.3 com LLC (STP e afins): 552; IPv6: 379; teste de enlace (loopback): 90 |
| `Uploading_Attack.pcap` | microssegundos | 262.144 | 0 | 0 | 100 | IEEE 802.3 com LLC (STP e afins): 218; IPv6: 172; teste de enlace (loopback): 36 |
| `VulnerabilityScan.pcap` | microssegundos | 262.144 | 0 | 0 | 99.253 | IEEE 802.3 com LLC (STP e afins): 35.957; IPv6: 27.614; teste de enlace (loopback): 5.843 |
| `XSS.pcap` | microssegundos | 262.144 | 0 | 0 | 509 | IPv6: 975; IEEE 802.3 com LLC (STP e afins): 654; teste de enlace (loopback): 108 |

## Como refazer

A partir da raiz do repositório, com os pcaps e o `MERGED_CSV` na pasta do dataset:

    python -m codigo.captura.calibrar_conjunto --dataset CICIoT2023 --processos 3

- O comando constrói o índice do `MERGED_CSV` (o processo do índice chega a cerca de 4,3 GB de memória),
  extrai os pcaps em paralelo, casa as linhas, roda o controle do vizinho e grava este relatório,
  `calibracao_conjunto_pcaps.csv`, `calibracao_conjunto_rotulos.csv` e `manifesto_calibracao_conjunto.json`.
  O manifesto traz o SHA-256 de cada pcap e de cada arquivo do `MERGED_CSV`.
- Os dados intermediários ficam em `dados/processed/calibracao_conjunto`, fora do git. Numa execução seguinte,
  o índice e as extrações são reaproveitados enquanto os arquivos e o código que gera cada um não
  mudarem; para refazer tudo, apague a pasta.
- Tempo total desta execução: 5,1 min; o pcap mais demorado levou 4,8 min. Os tempos das extrações reaproveitadas são os da execução em que foram feitas.
- Com os mesmos arquivos, os números saem iguais. Só mudam a data e os tempos.
