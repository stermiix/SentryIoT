# Calibração do extrator

Gerado por `python -m codigo.captura.calibrar` em 03/10/2026, com Python 3.11.2 e dpkt 1.9.8.

O extrator (`codigo/captura/extrator.py`) foi executado sobre pcaps do CICIoT2023 e a saída
foi comparada, coluna a coluna, com os CSVs publicados pelos autores do dataset.

## Escopo

A comparação cobre 2 pcaps, os que estão disponíveis localmente com o CSV oficial correspondente: `DictionaryBruteForce` (janela de 10), `Recon-PortScan` (janela de 10).

O CICIoT2023 tem 34 classes. Os autores agregam os quadros em janelas de 10 em 15 delas e em
janelas de 100 nas 19 classes de DDoS, DoS e Mirai. O resultado abaixo vale para os pcaps e
para os tamanhos de janela listados. As classes sem pcap disponível não foram conferidas.

## Resultado

| pcap | janela | pacotes | quadros IPv4 e ARP | pedaços de 10 MB | linhas extraídas | linhas oficiais | linhas iguais |
|---|---|---|---|---|---|---|---|
| `DictionaryBruteForce` | 10 | 133.138 | 130.632 | 4 | 13.064 | 13.064 | 13.064 |
| `Recon-PortScan` | 10 | 831.856 | 822.771 | 21 | 82.284 | 82.284 | 82.284 |

As 39 colunas são comparadas com tolerância relativa de 1e-09 e absoluta de 1e-12. Maior desvio relativo observado entre valores considerados iguais: 9.72e-13, na coluna `IAT` de `Recon-PortScan`.

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

Nenhuma divergência: todas as linhas dos CSVs oficiais conferidos foram reproduzidas nas 39 colunas.

## Como a comparação é feita

1. O tamanho da janela de cada pcap é lido do CSV oficial: é o maior valor da coluna
   `Number`, o de uma janela completa.
2. O pcap é dividido em pedaços como faz o `tcpdump -C 10`: um pedaço novo começa quando o
   atual já passou de 10.000.000 de bytes.
3. Cada pedaço é processado por um extrator novo, de modo que a janela e o intervalo entre
   quadros recomeçam a cada pedaço, como no processamento original.
4. Os autores juntam os CSVs dos pedaços sem ordem definida. Por isso os blocos de linhas são
   encaixados no CSV oficial na ordem em que ele os traz, cada bloco usado uma vez.
5. As 39 colunas são comparadas linha a linha. Campo vazio só é igual a campo vazio, e
   infinito só é igual a infinito.

## Particularidades do código dos autores reproduzidas pelo extrator

O classificador é treinado com os CSVs oficiais, então o extrator repete estes comportamentos:

- A coluna `IRC` é marcada pela porta TCP 21.
- A coluna `LLC` vale 1 em todo quadro IPv4, igual à coluna `IPv`.
- A coluna `SMTP` só é marcada em TCP; tráfego UDP na porta 25 não a ativa.
- Quadros IPv6 não geram linha.
- A última janela de cada pedaço pode ficar incompleta. Com um único quadro, `Std` e
  `Variance` ficam vazios e `Rate` é infinito.

## Diferenças conhecidas em relação ao código dos autores

- Quadro IPv4 com cabeçalho ilegível é ignorado pelo extrator. No código dos autores ele
  interrompe o processamento do pedaço inteiro. Como a quantidade de linhas bate, isso não
  ocorreu nos pcaps conferidos.
- O código dos autores trata o instante 0 como ausência de quadro anterior. O extrator só
  considera ausente o quadro anterior no início da leitura. A diferença só aparece em
  capturas com instante exatamente igual a zero.
- O extrator lê capturas com fração de tempo em nanossegundos. Não há referência dos autores
  para esse formato.
- O extrator decodifica só os primeiros 1600 bytes de cada quadro, o que cobre todos os
  cabeçalhos usados na medição. Um quadro maior que isso cuja decodificação completa falhe
  é descartado pelo código dos autores e mantido pelo extrator.
