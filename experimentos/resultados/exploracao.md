# Exploração do MERGED_CSV

Gerado por `python -m codigo.classificador.explorar` em 04/10/2026, com Python 3.11.2, pandas 3.0.6 e numpy 2.4.6.

Todos os números vêm da leitura completa do `MERGED_CSV` do CICIoT2023 (Neto et al., 2023), e não
da amostra de treino. As classes estão na grafia dos autores do dataset, e as categorias são as de
`codigo/classificador/mapeamento.py`.

## Resumo

- 45.019.234 linhas em 63 arquivos, com 39 features e a coluna `Label`.
- DDoS e DoS somam 89,48% das linhas, e o tráfego benigno é 2,34%.
- A maior classe (`DDoS-ICMP_Flood`) tem 5.763,6 vezes as linhas da menor (`Uploading_Attack`).
- A janela completa é de 100 quadros em 19 classes e de 10 em 15.
- Há valores vazios em `Std` e `Variance` e infinitos em `Rate`.
- 9 das 39 colunas podem ser recalculadas a partir das outras em todas as linhas: `Variance`, `Tot size`, `LLC`, `ARP`, `Tot sum`, `ack_count`, `syn_count`, `fin_count` e `rst_count`.
- 58,78% das linhas repetem as 39 features de outra linha, e 29,49% têm uma combinação de valores que também aparece em outra categoria.
- Por causa dessas combinações, o acerto em 8 categorias não passa de 92,87% para quem vê só as 39 features e é avaliado no conjunto completo, na proporção natural das classes. Esse valor não é uma propriedade das 39 features: muda com o tamanho e com a mistura de classes do conjunto avaliado, e um modelo avaliado numa amostra pode passar dele de forma legítima (seção 8).
- 9 arquivos terminam no meio de uma linha, truncados já na fonte oficial.

## 1. Arquivos

63 arquivos lidos, com 45.019.234 linhas de dados e 9.300.139.459 bytes no total.
O menor arquivo tem 65.723 linhas, o maior tem 920.543 e a mediana é de 712.220.

9 arquivos terminam no meio de uma linha, sem a quebra de linha final. A linha incompleta de cada um ficou fora de todas as contagens. As linhas que viriam depois do corte não fazem parte deste relatório. O corte está na origem, e não na cópia local: baixados de novo da fonte oficial em 04/10/2026, os arquivos do `MERGED_CSV` com esse defeito e os três CSVs por ataque de `DoS-UDP_Flood` que também terminam no meio de uma linha vieram idênticos byte a byte.

| Arquivo | Linhas completas | Bytes |
|---|---|---|
| `Merged42.csv` | 871.729 | 180.077.709 |
| `Merged44.csv` | 725.936 | 149.972.599 |
| `Merged46.csv` | 678.327 | 140.142.359 |
| `Merged47.csv` | 657.625 | 135.841.629 |
| `Merged48.csv` | 657.629 | 135.841.629 |
| `Merged49.csv` | 642.735 | 132.769.679 |
| `Merged50.csv` | 601.084 | 124.168.219 |
| `Merged51.csv` | 214.393 | 44.297.519 |
| `Merged52.csv` | 65.723 | 13.578.019 |

## 2. Linhas por categoria

| Categoria | Classes | Linhas | % do total | Menor % em um arquivo | Maior % em um arquivo |
|---|---|---|---|---|---|
| DDoS | 12 | 32.536.197 | 72,27% | 72,12% | 72,62% |
| DoS | 4 | 7.746.554 | 17,21% | 16,92% | 17,37% |
| Mirai | 3 | 2.521.731 | 5,60% | 5,53% | 5,66% |
| Recon | 5 | 661.121 | 1,47% | 1,44% | 1,51% |
| Spoofing | 2 | 465.937 | 1,03% | 1,01% | 1,09% |
| Web | 6 | 23.799 | 0,05% | 0,04% | 0,06% |
| BruteForce | 1 | 12.522 | 0,03% | 0,02% | 0,03% |
| Benign | 1 | 1.051.373 | 2,34% | 2,24% | 2,40% |

DDoS e DoS somam 89,48% das linhas. O tráfego benigno é 2,34%, e as outras cinco categorias de ataque somam 8,19%.
As duas últimas colunas mostram quanto a proporção muda de um arquivo para outro.

## 3. Linhas por classe

| Classe | Categoria | Linhas | % do total |
|---|---|---|---|
| `DDoS-ICMP_Flood` | DDoS | 6.893.259 | 15,3118% |
| `DDoS-UDP_Flood` | DDoS | 5.181.027 | 11,5085% |
| `DDoS-TCP_Flood` | DDoS | 4.306.086 | 9,5650% |
| `DDoS-PSHACK_Flood` | DDoS | 3.920.372 | 8,7082% |
| `DDoS-SYN_Flood` | DDoS | 3.886.130 | 8,6322% |
| `DDoS-RSTFINFlood` | DDoS | 3.872.808 | 8,6026% |
| `DDoS-SynonymousIP_Flood` | DDoS | 3.445.659 | 7,6537% |
| `DoS-UDP_Flood` | DoS | 3.177.323 | 7,0577% |
| `DoS-TCP_Flood` | DoS | 2.558.256 | 5,6826% |
| `DoS-SYN_Flood` | DoS | 1.942.176 | 4,3141% |
| `BenignTraffic` | Benign | 1.051.373 | 2,3354% |
| `Mirai-greeth_flood` | Mirai | 949.381 | 2,1088% |
| `Mirai-udpplain` | Mirai | 852.695 | 1,8941% |
| `Mirai-greip_flood` | Mirai | 719.655 | 1,5986% |
| `DDoS-ICMP_Fragmentation` | DDoS | 433.157 | 0,9622% |
| `VulnerabilityScan` | Recon | 357.583 | 0,7943% |
| `MITM-ArpSpoofing` | Spoofing | 294.469 | 0,6541% |
| `DDoS-UDP_Fragmentation` | DDoS | 274.909 | 0,6106% |
| `DDoS-ACK_Fragmentation` | DDoS | 272.793 | 0,6059% |
| `DNS_Spoofing` | Spoofing | 171.468 | 0,3809% |
| `Recon-HostDiscovery` | Recon | 128.677 | 0,2858% |
| `Recon-OSScan` | Recon | 93.970 | 0,2087% |
| `Recon-PortScan` | Recon | 78.730 | 0,1749% |
| `DoS-HTTP_Flood` | DoS | 68.799 | 0,1528% |
| `DDoS-HTTP_Flood` | DDoS | 27.597 | 0,0613% |
| `DDoS-SlowLoris` | DDoS | 22.400 | 0,0498% |
| `DictionaryBruteForce` | BruteForce | 12.522 | 0,0278% |
| `BrowserHijacking` | Web | 5.630 | 0,0125% |
| `CommandInjection` | Web | 5.168 | 0,0115% |
| `SqlInjection` | Web | 5.022 | 0,0112% |
| `XSS` | Web | 3.705 | 0,0082% |
| `Backdoor_Malware` | Web | 3.078 | 0,0068% |
| `Recon-PingSweep` | Recon | 2.161 | 0,0048% |
| `Uploading_Attack` | Web | 1.196 | 0,0027% |

A razão entre a maior classe (`DDoS-ICMP_Flood`, 6.893.259 linhas) e a menor (`Uploading_Attack`, 1.196 linhas) é de 5.763,6 para 1.

As 34 classes estão presentes.

### Grafia dos rótulos

Nos arquivos, 33 das 34 classes presentes vêm com grafia diferente da canônica, que é a do dicionário dos autores do dataset. Na maioria só muda a caixa das letras. O nome é outro em: `BENIGN` no lugar de `BenignTraffic`. Passar o dicionário dos autores para maiúsculas, portanto, não basta para casar os rótulos.

## 4. Tamanho da janela por classe

A coluna `Number` traz a quantidade de quadros agregados em cada linha. O maior valor de cada
classe é o tamanho da janela completa, e os valores menores são janelas incompletas.

| Classe | Categoria | Maior `Number` | Linhas com a janela completa | % da classe | Menor `Number` |
|---|---|---|---|---|---|
| `DDoS-ACK_Fragmentation` | DDoS | 100 | 270.379 | 99,12% | 1 |
| `DDoS-UDP_Flood` | DDoS | 100 | 5.177.094 | 99,92% | 1 |
| `DDoS-SlowLoris` | DDoS | 100 | 22.338 | 99,72% | 1 |
| `DDoS-ICMP_Flood` | DDoS | 100 | 6.888.007 | 99,92% | 1 |
| `DDoS-RSTFINFlood` | DDoS | 100 | 3.869.849 | 99,92% | 1 |
| `DDoS-PSHACK_Flood` | DDoS | 100 | 3.917.387 | 99,92% | 1 |
| `DDoS-HTTP_Flood` | DDoS | 100 | 27.536 | 99,78% | 3 |
| `DDoS-UDP_Fragmentation` | DDoS | 100 | 272.437 | 99,10% | 1 |
| `DDoS-ICMP_Fragmentation` | DDoS | 100 | 429.297 | 99,11% | 1 |
| `DDoS-TCP_Flood` | DDoS | 100 | 4.302.712 | 99,92% | 1 |
| `DDoS-SYN_Flood` | DDoS | 100 | 3.883.112 | 99,92% | 1 |
| `DDoS-SynonymousIP_Flood` | DDoS | 100 | 3.443.038 | 99,92% | 1 |
| `DoS-TCP_Flood` | DoS | 100 | 2.556.253 | 99,92% | 1 |
| `DoS-HTTP_Flood` | DoS | 100 | 68.458 | 99,50% | 1 |
| `DoS-SYN_Flood` | DoS | 100 | 1.940.678 | 99,92% | 1 |
| `DoS-UDP_Flood` | DoS | 100 | 3.174.060 | 99,90% | 1 |
| `Mirai-greip_flood` | Mirai | 100 | 715.509 | 99,42% | 1 |
| `Mirai-greeth_flood` | Mirai | 100 | 943.733 | 99,41% | 1 |
| `Mirai-udpplain` | Mirai | 100 | 847.969 | 99,45% | 1 |
| `Recon-PingSweep` | Recon | 10 | 2.161 | 100,00% | 10 |
| `Recon-OSScan` | Recon | 10 | 93.942 | 99,97% | 1 |
| `VulnerabilityScan` | Recon | 10 | 357.498 | 99,98% | 1 |
| `Recon-PortScan` | Recon | 10 | 78.713 | 99,98% | 1 |
| `Recon-HostDiscovery` | Recon | 10 | 128.657 | 99,98% | 1 |
| `MITM-ArpSpoofing` | Spoofing | 10 | 294.296 | 99,94% | 1 |
| `DNS_Spoofing` | Spoofing | 10 | 171.410 | 99,97% | 1 |
| `SqlInjection` | Web | 10 | 5.021 | 99,98% | 1 |
| `CommandInjection` | Web | 10 | 5.166 | 99,96% | 5 |
| `Backdoor_Malware` | Web | 10 | 3.077 | 99,97% | 8 |
| `Uploading_Attack` | Web | 10 | 1.195 | 99,92% | 3 |
| `XSS` | Web | 10 | 3.703 | 99,95% | 3 |
| `BrowserHijacking` | Web | 10 | 5.626 | 99,93% | 2 |
| `DictionaryBruteForce` | BruteForce | 10 | 12.519 | 99,98% | 4 |
| `BenignTraffic` | Benign | 10 | 1.050.762 | 99,94% | 1 |

- Janela de 100: 19 classes, em DDoS, DoS e Mirai. 99,87% das linhas dessas classes têm a janela completa.
- Janela de 10: 15 classes, em Recon, Spoofing, Web, BruteForce e Benign. 99,95% das linhas dessas classes têm a janela completa.

Nenhuma linha das classes de janela 10 tem `Number` acima de 10. Nas classes de janela 100, 5.622 linhas (0,0131%) têm `Number` de até 10. A regra `Number` > 10 separa sozinha os dois grupos de classes em 99,9875% das linhas do conjunto.

## 5. Valores vazios e infinitos

| Coluna | Vazios | Infinitos | Em linhas com `Number` = 1 |
|---|---|---|---|
| `Rate` | 0 | 991 | 670 |
| `Std` | 670 | 0 | 670 |
| `Variance` | 670 | 0 | 670 |

As outras 36 colunas não têm valor vazio nem infinito. O conjunto tem 670 linhas com `Number` = 1.
Uma janela com um só quadro não tem variância amostral nem duração, o que deixa `Std` e `Variance`
vazios e `Rate` infinito. `Rate` também fica infinito quando todos os quadros da janela têm o mesmo
instante.

## 6. Faixa de valores por coluna

Mínimo e máximo ignoram valores vazios e infinitos.

| Coluna | Mínimo | Máximo | Linhas diferentes de zero | % das linhas |
|---|---|---|---|---|
| `Header_Length` | 0 | 60 | 37.841.679 | 84,0567% |
| `Protocol Type` | 0 | 47 | 45.005.889 | 99,9704% |
| `Time_To_Live` | 0 | 255 | 45.018.779 | 99,9990% |
| `Rate` | 1,3e-05 | 15.728.640 | 45.019.234 | 100,0000% |
| `fin_flag_number` | 0 | 1 | 5.129.922 | 11,3950% |
| `syn_flag_number` | 0 | 1 | 11.727.707 | 26,0504% |
| `rst_flag_number` | 0 | 1 | 5.612.671 | 12,4673% |
| `psh_flag_number` | 0 | 1 | 7.730.087 | 17,1706% |
| `ack_flag_number` | 0 | 1 | 11.504.529 | 25,5547% |
| `ece_flag_number` | 0 | 1 | 32.065 | 0,0712% |
| `cwr_flag_number` | 0 | 1 | 13.953 | 0,0310% |
| `ack_count` | 0 | 100 | 11.504.529 | 25,5547% |
| `syn_count` | 0 | 100 | 11.727.707 | 26,0504% |
| `fin_count` | 0 | 100 | 5.129.922 | 11,3950% |
| `rst_count` | 0 | 100 | 5.612.671 | 12,4673% |
| `HTTP` | 0 | 1 | 3.504.906 | 7,7854% |
| `HTTPS` | 0 | 1 | 6.477.364 | 14,3880% |
| `DNS` | 0 | 1 | 2.742.555 | 6,0920% |
| `Telnet` | 0 | 0,6 | 36.765 | 0,0817% |
| `SMTP` | 0 | 0,9 | 36.659 | 0,0814% |
| `SSH` | 0 | 1 | 138.884 | 0,3085% |
| `IRC` | 0 | 0,9 | 43.070 | 0,0957% |
| `TCP` | 0 | 1 | 29.260.050 | 64,9946% |
| `UDP` | 0 | 1 | 14.075.915 | 31,2664% |
| `DHCP` | 0 | 1 | 249.327 | 0,5538% |
| `ARP` | 0 | 1 | 4.403.470 | 9,7813% |
| `ICMP` | 0 | 1 | 9.437.320 | 20,9629% |
| `IGMP` | 0 | 1 | 29.768 | 0,0661% |
| `IPv` | 0 | 1 | 45.018.779 | 99,9990% |
| `LLC` | 0 | 1 | 45.018.779 | 99,9990% |
| `Tot sum` | 60 | 316.492 | 45.019.234 | 100,0000% |
| `Min` | 42 | 13.583 | 45.019.234 | 100,0000% |
| `Max` | 46 | 52.194 | 45.019.234 | 100,0000% |
| `AVG` | 46 | 13.583 | 45.019.234 | 100,0000% |
| `Std` | 0 | 11.655,4 | 11.826.983 | 26,2710% |
| `Tot size` | 46 | 13.583 | 45.019.234 | 100,0000% |
| `IAT` | -0,017818 | 78.612,0 | 45.018.923 | 99,9993% |
| `Number` | 1 | 100 | 45.019.234 | 100,0000% |
| `Variance` | 0 | 135.848.458 | 11.826.983 | 26,2710% |

Nenhuma coluna é constante.
Só `IAT` tem valores negativos, em 2 linhas.
Todas as linhas respeitam `Min` ≤ `AVG` ≤ `Max`.

## 7. Colunas redundantes

Pares de colunas com valores idênticos em todas as linhas, procurados entre todos os pares das 39 colunas: `IPv` e `LLC`; `AVG` e `Tot size`.

Relações conferidas linha a linha:

| Coluna | Igual a | Linhas conferidas | Linhas fora da tolerância | Maior desvio relativo |
|---|---|---|---|---|
| `Variance` | `Std`² | 45.019.234 | 0 | 8,0e-15 |
| `Tot size` | `AVG` | 45.019.234 | 0 | 0 |
| `LLC` | `IPv` | 45.019.234 | 0 | 0 |
| `ARP` | 1 − `IPv` | 45.019.234 | 0 | 1,8e-14 |
| `Tot sum` | `AVG` × `Number` | 45.019.234 | 0 | 3,9e-16 |
| `ack_count` | `ack_flag_number` × `Number` | 45.019.234 | 0 | 8,1e-15 |
| `syn_count` | `syn_flag_number` × `Number` | 45.019.234 | 0 | 8,1e-15 |
| `fin_count` | `fin_flag_number` × `Number` | 45.019.234 | 0 | 8,1e-15 |
| `rst_count` | `rst_flag_number` × `Number` | 45.019.234 | 0 | 8,1e-15 |

A tolerância é relativa, de 1e-09, com piso absoluto de 1e-12. Vazio só é igual a vazio, e infinito só é igual a infinito.
9 colunas podem ser recalculadas a partir das outras em todas as linhas: `Variance`, `Tot size`, `LLC`, `ARP`, `Tot sum`, `ack_count`, `syn_count`, `fin_count` e `rst_count`.

## 8. Linhas repetidas

Duas linhas são repetidas quando têm os mesmos valores nas 39 features. O rótulo não entra na
comparação.

- As 45.019.234 linhas formam 20.383.063 combinações distintas das 39 features.
- 26.464.368 linhas (58,78%) têm uma combinação que aparece mais de uma vez. A combinação mais repetida aparece em 1.156 linhas.
- 13.776.398 linhas (30,60%) têm uma combinação que também aparece com outro rótulo.
- 13.275.110 linhas (29,49%) têm uma combinação que também aparece com outra categoria.

| Classe | Categoria | Linhas | Repetidas | % da classe | Com outro rótulo | Com outra categoria |
|---|---|---|---|---|---|---|
| `DDoS-ACK_Fragmentation` | DDoS | 272.793 | 2.384 | 0,87% | 4 | 0 |
| `DDoS-UDP_Flood` | DDoS | 5.181.027 | 3.475.374 | 67,08% | 2.730.279 | 2.730.277 |
| `DDoS-SlowLoris` | DDoS | 22.400 | 0 | 0,00% | 0 | 0 |
| `DDoS-ICMP_Flood` | DDoS | 6.893.259 | 5.306.002 | 76,97% | 0 | 0 |
| `DDoS-RSTFINFlood` | DDoS | 3.872.808 | 2.814.571 | 72,68% | 4 | 2 |
| `DDoS-PSHACK_Flood` | DDoS | 3.920.372 | 2.499.585 | 63,76% | 102 | 85 |
| `DDoS-HTTP_Flood` | DDoS | 27.597 | 8 | 0,03% | 8 | 8 |
| `DDoS-UDP_Fragmentation` | DDoS | 274.909 | 2.862 | 1,04% | 0 | 0 |
| `DDoS-ICMP_Fragmentation` | DDoS | 433.157 | 3.781 | 0,87% | 0 | 0 |
| `DDoS-TCP_Flood` | DDoS | 4.306.086 | 2.993.966 | 69,53% | 2.743.117 | 2.743.117 |
| `DDoS-SYN_Flood` | DDoS | 3.886.130 | 2.393.631 | 61,59% | 2.276.395 | 2.084.788 |
| `DDoS-SynonymousIP_Flood` | DDoS | 3.445.659 | 2.527.179 | 73,34% | 2.332.961 | 2.029.710 |
| `DoS-TCP_Flood` | DoS | 2.558.256 | 1.631.533 | 63,78% | 1.571.761 | 1.571.760 |
| `DoS-HTTP_Flood` | DoS | 68.799 | 580 | 0,84% | 52 | 18 |
| `DoS-SYN_Flood` | DoS | 1.942.176 | 983.690 | 50,65% | 945.522 | 945.499 |
| `DoS-UDP_Flood` | DoS | 3.177.323 | 1.526.101 | 48,03% | 1.142.603 | 1.142.603 |
| `Mirai-greip_flood` | Mirai | 719.655 | 42.010 | 5,84% | 0 | 0 |
| `Mirai-greeth_flood` | Mirai | 949.381 | 81.711 | 8,61% | 0 | 0 |
| `Mirai-udpplain` | Mirai | 852.695 | 129.562 | 15,19% | 0 | 0 |
| `Recon-PingSweep` | Recon | 2.161 | 5 | 0,23% | 5 | 0 |
| `Recon-OSScan` | Recon | 93.970 | 3.173 | 3,38% | 2.604 | 214 |
| `VulnerabilityScan` | Recon | 357.583 | 1.939 | 0,54% | 1.370 | 1.182 |
| `Recon-PortScan` | Recon | 78.730 | 3.505 | 4,45% | 2.683 | 148 |
| `Recon-HostDiscovery` | Recon | 128.677 | 1.175 | 0,91% | 1.095 | 928 |
| `MITM-ArpSpoofing` | Spoofing | 294.469 | 27.799 | 9,44% | 21.486 | 20.611 |
| `DNS_Spoofing` | Spoofing | 171.468 | 5.693 | 3,32% | 1.448 | 1.261 |
| `SqlInjection` | Web | 5.022 | 1 | 0,02% | 1 | 1 |
| `CommandInjection` | Web | 5.168 | 40 | 0,77% | 5 | 5 |
| `Backdoor_Malware` | Web | 3.078 | 26 | 0,84% | 24 | 24 |
| `Uploading_Attack` | Web | 1.196 | 0 | 0,00% | 0 | 0 |
| `XSS` | Web | 3.705 | 8 | 0,22% | 8 | 8 |
| `BrowserHijacking` | Web | 5.630 | 154 | 2,74% | 149 | 149 |
| `DictionaryBruteForce` | BruteForce | 12.522 | 19 | 0,15% | 19 | 19 |
| `BenignTraffic` | Benign | 1.051.373 | 6.301 | 0,60% | 2.693 | 2.693 |

Um classificador que veja só as 39 features dá a mesma resposta para todas as linhas de uma combinação. A regra de maior acerto global responde, em cada combinação, a categoria mais frequente nela, e as linhas das outras categorias são erro. No empate vale a primeira categoria na ordem da tabela, e por isso DDoS tem preferência sobre DoS. A tabela dá os erros e o acerto de cada categoria nessa regra, medidos no conjunto completo.

| Categoria | Linhas | Erros na regra de maior acerto global | Acerto nessa regra |
|---|---|---|---|
| DDoS | 32.536.197 | 806.209 | 97,52% |
| DoS | 7.746.554 | 2.399.296 | 69,03% |
| Mirai | 2.521.731 | 0 | 100,00% |
| Recon | 661.121 | 1.225 | 99,81% |
| Spoofing | 465.937 | 357 | 99,92% |
| Web | 23.799 | 179 | 99,25% |
| BruteForce | 12.522 | 17 | 99,86% |
| Benign | 1.051.373 | 2.433 | 99,77% |
| Total | 45.019.234 | 3.209.716 | 92,87% |

Só a linha Total é um limite superior: nenhuma regra que dependa só das 39 features acerta mais que 92,87% das linhas do conjunto completo. Os valores por categoria não são limites. São o recall de cada categoria na regra de maior acerto global, e outra regra os redistribui. Na regra que responde DoS em toda combinação que tenha alguma linha de DoS, o acerto de DoS é de 100,00%, o de DDoS é de 70,53% e o acerto global é de 78,69%.

O limite da linha Total vale para a avaliação no conjunto completo, na proporção natural das classes, e conta só a coincidência exata dos 39 valores. Não é uma propriedade das 39 features em si: muda com o tamanho e com a mistura de classes do conjunto avaliado. Um modelo avaliado numa amostra pode passar de 92,87% de forma legítima, e o limite de um conjunto de teste precisa ser calculado nesse conjunto.

Rótulos que dividem a mesma combinação de valores, em ordem de linhas envolvidas (15 de 142 conjuntos de rótulos):

| Rótulos com a mesma combinação | Linhas |
|---|---|
| `DDoS-SYN_Flood`, `DDoS-SynonymousIP_Flood` e `DoS-SYN_Flood` | 4.840.276 |
| `DDoS-TCP_Flood` e `DoS-TCP_Flood` | 4.314.877 |
| `DDoS-UDP_Flood` e `DoS-UDP_Flood` | 3.872.876 |
| `DDoS-SYN_Flood` e `DDoS-SynonymousIP_Flood` | 494.855 |
| `DDoS-SYN_Flood` e `DoS-SYN_Flood` | 162.476 |
| `DDoS-SynonymousIP_Flood` e `DoS-SYN_Flood` | 57.141 |
| `Recon-OSScan` e `Recon-PortScan` | 4.674 |
| `VulnerabilityScan`, `Recon-HostDiscovery`, `MITM-ArpSpoofing`, `DNS_Spoofing`, `BrowserHijacking`, `DictionaryBruteForce` e `BenignTraffic` | 2.965 |
| `MITM-ArpSpoofing` e `BenignTraffic` | 2.925 |
| `Recon-HostDiscovery`, `MITM-ArpSpoofing`, `DNS_Spoofing` e `BenignTraffic` | 2.506 |
| `MITM-ArpSpoofing`, `DNS_Spoofing` e `BenignTraffic` | 1.730 |
| `Recon-HostDiscovery`, `MITM-ArpSpoofing`, `DNS_Spoofing`, `BrowserHijacking` e `BenignTraffic` | 1.584 |
| `VulnerabilityScan`, `Recon-HostDiscovery`, `MITM-ArpSpoofing`, `DNS_Spoofing`, `XSS`, `BrowserHijacking` e `BenignTraffic` | 1.564 |
| `VulnerabilityScan`, `Recon-HostDiscovery`, `MITM-ArpSpoofing`, `DNS_Spoofing`, `Backdoor_Malware`, `BrowserHijacking` e `BenignTraffic` | 1.436 |
| `VulnerabilityScan`, `Recon-HostDiscovery`, `MITM-ArpSpoofing`, `DNS_Spoofing` e `BenignTraffic` | 1.234 |

## 9. Valores de `Protocol Type`

`Protocol Type` é o número de protocolo IP mais frequente na janela.

| `Protocol Type` | Protocolo | Linhas | % das linhas |
|---|---|---|---|
| 0 | ARP (sem protocolo IP) | 13.345 | 0,0296% |
| 1 | ICMP | 7.321.514 | 16,2631% |
| 2 | IGMP | 4 | 0,0000% |
| 6 | TCP | 26.211.324 | 58,2225% |
| 17 | UDP | 9.817.966 | 21,8084% |
| 47 | GRE | 1.655.081 | 3,6764% |

## 10. Conferência com os CSVs por ataque

O dataset também traz uma pasta de CSVs por ataque, com as mesmas 39 colunas e sem rótulo: a
classe é o nome da pasta. A tabela compara a quantidade de linhas dessas pastas com a do
`MERGED_CSV`. A diferença é a quantidade nos CSVs por ataque menos a do `MERGED_CSV`.

| Classe | Arquivos | Linhas nos CSVs por ataque | Linhas no `MERGED_CSV` | Diferença | % dos CSVs por ataque |
|---|---|---|---|---|---|
| `DDoS-ACK_Fragmentation` | 13 | 285.075 | 272.793 | 12.282 | 4,31% |
| `DDoS-UDP_Flood` | 21 | 5.412.231 | 5.181.027 | 231.204 | 4,27% |
| `DDoS-SlowLoris` | 1 | 23.426 | 22.400 | 1.026 | 4,38% |
| `DDoS-ICMP_Flood` | 27 | 7.200.501 | 6.893.259 | 307.242 | 4,27% |
| `DDoS-RSTFINFlood` | 16 | 4.045.279 | 3.872.808 | 172.471 | 4,26% |
| `DDoS-PSHACK_Flood` | 16 | 4.094.772 | 3.920.372 | 174.400 | 4,26% |
| `DDoS-HTTP_Flood` | 1 | 28.790 | 27.597 | 1.193 | 4,14% |
| `DDoS-UDP_Fragmentation` | 13 | 286.925 | 274.909 | 12.016 | 4,19% |
| `DDoS-ICMP_Fragmentation` | 20 | 452.490 | 433.157 | 19.333 | 4,27% |
| `DDoS-TCP_Flood` | 18 | 4.497.649 | 4.306.086 | 191.563 | 4,26% |
| `DDoS-SYN_Flood` | 16 | 4.059.179 | 3.886.130 | 173.049 | 4,26% |
| `DDoS-SynonymousIP_Flood` | 14 | 3.598.133 | 3.445.659 | 152.474 | 4,24% |
| `DoS-TCP_Flood` | 11 | 2.671.430 | 2.558.256 | 113.174 | 4,24% |
| `DoS-HTTP_Flood` | 2 | 71.861 | 68.799 | 3.062 | 4,26% |
| `DoS-SYN_Flood` | 8 | 2.028.836 | 1.942.176 | 86.660 | 4,27% |
| `DoS-UDP_Flood` | 17 | 3.072.990 | 3.177.323 | -104.333 | -3,40% |
| `Mirai-greip_flood` | 22 | 751.646 | 719.655 | 31.991 | 4,26% |
| `Mirai-greeth_flood` | 29 | 991.834 | 949.381 | 42.453 | 4,28% |
| `Mirai-udpplain` | 25 | 890.574 | 852.695 | 37.879 | 4,25% |
| `Recon-PingSweep` | 1 | 2.262 | 2.161 | 101 | 4,47% |
| `Recon-OSScan` | 1 | 98.259 | 93.970 | 4.289 | 4,36% |
| `VulnerabilityScan` | 1 | 373.351 | 357.583 | 15.768 | 4,22% |
| `Recon-PortScan` | 1 | 82.284 | 78.730 | 3.554 | 4,32% |
| `Recon-HostDiscovery` | 1 | 134.378 | 128.677 | 5.701 | 4,24% |
| `MITM-ArpSpoofing` | 2 | 307.560 | 294.469 | 13.091 | 4,26% |
| `DNS_Spoofing` | 1 | 178.898 | 171.468 | 7.430 | 4,15% |
| `SqlInjection` | 1 | 5.245 | 5.022 | 223 | 4,25% |
| `CommandInjection` | 1 | 5.409 | 5.168 | 241 | 4,46% |
| `Backdoor_Malware` | 1 | 3.218 | 3.078 | 140 | 4,35% |
| `Uploading_Attack` | 1 | 1.252 | 1.196 | 56 | 4,47% |
| `XSS` | 1 | 3.846 | 3.705 | 141 | 3,67% |
| `BrowserHijacking` | 1 | 5.859 | 5.630 | 229 | 3,91% |
| `DictionaryBruteForce` | 1 | 13.064 | 12.522 | 542 | 4,15% |
| `BenignTraffic` | 4 | 1.098.191 | 1.051.373 | 46.818 | 4,26% |
| Total das classes com CSVs por ataque inteiros | 292 | 43.703.707 | 41.841.911 | 1.861.796 | 4,26% |

A linha de total soma só as 33 classes cujos CSVs por ataque estão inteiros. Nelas, o `MERGED_CSV` tem 4,26% menos linhas que os CSVs por ataque, e a diferença por classe vai de 3,67% a 4,47%. O `MERGED_CSV` é embaralhado, então linhas perdidas em arquivos truncados faltam em todas as classes em proporção parecida. Aplicada a todas as classes, essa proporção corresponde a cerca de 2,0 milhões de linhas a menos no `MERGED_CSV`.

`DoS-UDP_Flood` fica fora do total porque 3 arquivos por ataque terminam no meio de uma linha, e a linha incompleta não foi contada: `DoS-UDP_Flood7.pcap.csv`, `DoS-UDP_Flood8.pcap.csv` e `DoS-UDP_Flood9.pcap.csv`. Com a referência incompleta, a diferença dessa classe não mede o que falta ao `MERGED_CSV`. Somadas todas as classes, a diferença seria de 1.757.463 linhas, ou 3,76%.

## Como os números foram obtidos

- Os arquivos são lidos em ordem de nome, linha a linha. Linha em branco é ignorada, e rótulo
  desconhecido ou linha com a quantidade errada de campos interrompe a execução.
- Os valores são convertidos para ponto flutuante de 64 bits sem perda (`float_precision="round_trip"`).
- As linhas repetidas são encontradas por um hash de 64 bits das 39 colunas
  (`pandas.util.hash_pandas_object`). Com dezenas de milhões de linhas, a chance de duas linhas
  diferentes terem o mesmo hash é desprezível para estas contagens.
- Os percentuais são sobre o total de linhas completas lidas, salvo quando a coluna diz outra coisa.
