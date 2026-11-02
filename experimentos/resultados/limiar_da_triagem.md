# Limiar de confiança da triagem

Gerado por `python -m codigo.reprodutor.limiar`, a partir dos resultados da avaliação dos 38 pcaps (`python -m codigo.reprodutor.avaliar`, relatório em `reproducao_dos_pcaps.md`).

A regra testada é a da skill de triagem: o incidente com confiança do classificador abaixo do limiar recebe o veredito "duvidoso". Um incidente é verdadeiro quando o pcap não é benigno, quando alguma janela dele tem quadro de um atacante do dataset e quando a categoria do incidente é a do pcap, com DDoS e DoS como uma família só. Os outros são falsos.

São 212 incidentes: 196 verdadeiros e 16 falsos. 117 ficam inteiros fora do trecho de teste do modelo, e 95 têm janela no teste.

Dos 16 falsos, 1 é alarme em pcap benigno e 15 são incidentes de um pcap de ataque com a categoria errada. Para a triagem, os dois pedem o veredito duvidoso: no segundo caso o ataque existe, mas a categoria que guia a resposta está errada.

Cada par de colunas diz quantos incidentes ficam abaixo do limiar: falsos pegos e verdadeiros marcados.

| Limiar | Falsos, todos | Verdadeiros, todos | Falsos, fora do teste | Verdadeiros, fora do teste | Falsos, no teste | Verdadeiros, no teste |
| --- | --- | --- | --- | --- | --- | --- |
| 0,50 | 7 de 16 | 2 de 196 | 0 de 0 | 0 de 117 | 7 de 16 | 2 de 79 |
| 0,55 | 8 de 16 | 3 de 196 | 0 de 0 | 0 de 117 | 8 de 16 | 3 de 79 |
| 0,60 (escolhido) | 11 de 16 | 8 de 196 | 0 de 0 | 1 de 117 | 11 de 16 | 7 de 79 |
| 0,65 | 12 de 16 | 15 de 196 | 0 de 0 | 1 de 117 | 12 de 16 | 14 de 79 |
| 0,70 | 13 de 16 | 22 de 196 | 0 de 0 | 3 de 117 | 13 de 16 | 19 de 79 |
| 0,75 | 14 de 16 | 29 de 196 | 0 de 0 | 6 de 117 | 14 de 16 | 23 de 79 |
| 0,80 | 15 de 16 | 42 de 196 | 0 de 0 | 15 de 117 | 15 de 16 | 27 de 79 |

## A escolha

O limiar é escolhido só com os incidentes fora do teste: é o menor dos limiares que pegam ali o máximo de falsos sem marcar nenhum verdadeiro. O empate é resolvido para baixo porque marcar um ataque verdadeiro como duvidoso custa mais do que deixar passar um falso, que ainda passa pelo agente de decisão e pela aprovação humana das ações de risco alto. A coluna do teste é a conferência. Atenção: fora do teste não sobra incidente falso, e a regra não tem o que escolher. O 0,60 vem da decisão de 25/10/2026, quando as trocas entre DDoS e DoS contavam como falsas, e foi mantido sem ajuste: aqui, a conferência é só a coluna do teste.

Exigir também poucas janelas troca falsos pegos por verdadeiros poupados. Com todos os incidentes:

| Limiar | Condição de janelas | Falsos pegos | Verdadeiros marcados |
| --- | --- | --- | --- |
| 0,60 | nenhuma | 11 de 16 | 8 de 196 |
| 0,60 | menos de 10 | 6 de 16 | 2 de 196 |
| 0,60 | menos de 5 | 3 de 16 | 0 de 196 |
| 0,65 | nenhuma | 12 de 16 | 15 de 196 |
| 0,65 | menos de 10 | 6 de 16 | 4 de 196 |
| 0,65 | menos de 5 | 3 de 16 | 0 de 196 |

A skill fica sem a condição de janelas: ela poupa poucos verdadeiros e deixa passar boa parte dos falsos que o limiar pegaria.

Verdadeiros abaixo de 0,60, que a triagem passa a marcar como duvidosos:

| Pcap | Categoria | Confiança | Janelas |
| --- | --- | --- | --- |
| `Mirai-udpplain.pcap` | Mirai | 0,46 | 30 |
| `DDoS-SlowLoris.pcap` | DoS | 0,48 | 2419 |
| `DDoS-UDP_Fragmentation.pcap` | DoS | 0,50 | 43 |
| `DDoS-UDP_Flood.pcap` | DoS | 0,59 | 21 |
| `DoS-HTTP_Flood1.pcap` | DoS | 0,59 | 142 |
| `VulnerabilityScan.pcap` | Recon | 0,59 | 8 |
| `VulnerabilityScan.pcap` | Recon | 0,59 | 9 |
| `VulnerabilityScan.pcap` | Recon | 0,59 | 20 |

## O que o limiar não pega

1 dos 16 falsos tem confiança de 0,80 ou mais, e nenhum limiar de confiança separa esses casos dos verdadeiros sem marcar boa parte dos ataques.
