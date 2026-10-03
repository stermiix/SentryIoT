# Calibração do extrator

Gerado por `python -m codigo.captura.calibrar` em 03/10/2026, com Python 3.11.2 e dpkt 1.9.8.

O extrator (`codigo/captura/extrator.py`) foi executado sobre os pcaps do CICIoT2023 e a
saída foi comparada, coluna a coluna, com os CSVs publicados pelos autores do dataset.

## Resultado

| pcap | pacotes | quadros IPv4 e ARP | pedaços de 10 MB | linhas extraídas | linhas oficiais | linhas iguais |
|---|---|---|---|---|---|---|
| `DictionaryBruteForce` | 133.138 | 130.632 | 4 | 13.064 | 13.064 | 13.064 |
| `Recon-PortScan` | 831.856 | 822.771 | 21 | 82.284 | 82.284 | 82.284 |

Tolerância usada nos valores decimais: 1e-09 (relativa). Maior desvio relativo observado entre valores considerados iguais: 9.72e-13. Valores inteiros são comparados sem tolerância.

## Quadros fora do filtro

O extrator mantém apenas quadros Ethernet de tipo IPv4 ou ARP, como o código dos autores.

| pcap | tipo do quadro | quadros |
|---|---|---|
| `DictionaryBruteForce` | IPv6 | 1.066 |
| `DictionaryBruteForce` | IEEE 802.3 com LLC (STP e afins) | 1.236 |
| `DictionaryBruteForce` | teste de enlace (loopback) | 204 |
| `Recon-PortScan` | IPv6 | 3.915 |
| `Recon-PortScan` | IEEE 802.3 com LLC (STP e afins) | 4.438 |
| `Recon-PortScan` | teste de enlace (loopback) | 732 |

## Divergências

Nenhuma divergência: todas as linhas dos CSVs oficiais foram reproduzidas nas 39 colunas.

## Como a comparação é feita

1. O pcap é dividido em pedaços como faz o `tcpdump -C 10`: um pedaço novo começa quando o
   atual já passou de 10.000.000 de bytes.
2. Cada pedaço é processado por um extrator novo, de modo que a janela de 10 quadros e o
   intervalo entre quadros recomeçam a cada pedaço, como no processamento original.
3. Os autores juntam os CSVs dos pedaços sem ordem definida. Por isso os blocos de linhas são
   encaixados no CSV oficial na ordem em que ele os traz, cada bloco usado uma vez.
4. As 39 colunas são comparadas linha a linha. Campo vazio só é igual a campo vazio, e
   infinito só é igual a infinito.

## Particularidades do código dos autores reproduzidas pelo extrator

O classificador é treinado com os CSVs oficiais, então o extrator repete estes comportamentos:

- A coluna `IRC` é marcada pela porta TCP 21.
- A coluna `LLC` vale 1 em todo quadro IPv4, igual à coluna `IPv`.
- A coluna `SMTP` só é marcada em TCP; tráfego UDP na porta 25 não a ativa.
- Quadros IPv6 não geram linha.
- A última janela de cada pedaço pode ter menos de 10 quadros. Com um único quadro, `Std` e
  `Variance` ficam vazios e `Rate` é infinito.
