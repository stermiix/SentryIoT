# Limiar de confiança da triagem

Gerado por `python -m codigo.reprodutor.limiar`, a partir dos resultados da avaliação dos 38 pcaps (`python -m codigo.reprodutor.avaliar`, relatório em `reproducao_dos_pcaps.md`).

A regra testada é a da skill de triagem: o incidente com confiança do classificador abaixo do limiar recebe o veredito "duvidoso". Um incidente é verdadeiro quando o pcap não é benigno, quando alguma janela dele tem quadro de um atacante do dataset e quando a categoria do incidente é a do pcap. Os outros são falsos.

São 212 incidentes: 171 verdadeiros e 41 falsos. 117 ficam inteiros fora do trecho de teste do modelo, e 95 têm janela no teste.

Dos 41 falsos, 1 são alarmes em pcap benigno e 40 são incidentes de um pcap de ataque com a categoria errada. Para a triagem, os dois pedem o veredito duvidoso: no segundo caso o ataque existe, mas a categoria que guia a resposta está errada.

Cada par de colunas diz quantos incidentes ficam abaixo do limiar: falsos pegos e verdadeiros marcados.

| Limiar | Falsos, todos | Verdadeiros, todos | Falsos, fora do teste | Verdadeiros, fora do teste | Falsos, no teste | Verdadeiros, no teste |
| --- | --- | --- | --- | --- | --- | --- |
| 0,50 | 8 de 41 | 1 de 171 | 0 de 12 | 0 de 105 | 8 de 29 | 1 de 66 |
| 0,55 | 10 de 41 | 1 de 171 | 0 de 12 | 0 de 105 | 10 de 29 | 1 de 66 |
| 0,60 (escolhido) | 14 de 41 | 5 de 171 | 1 de 12 | 0 de 105 | 13 de 29 | 5 de 66 |
| 0,65 | 15 de 41 | 12 de 171 | 1 de 12 | 0 de 105 | 14 de 29 | 12 de 66 |
| 0,70 | 16 de 41 | 19 de 171 | 1 de 12 | 2 de 105 | 15 de 29 | 17 de 66 |
| 0,75 | 17 de 41 | 26 de 171 | 1 de 12 | 5 de 105 | 16 de 29 | 21 de 66 |
| 0,80 | 18 de 41 | 39 de 171 | 1 de 12 | 14 de 105 | 17 de 29 | 25 de 66 |

## A escolha

O limiar é escolhido só com os incidentes fora do teste: é o menor dos limiares que pegam ali o máximo de falsos sem marcar nenhum verdadeiro. O empate é resolvido para baixo porque marcar um ataque verdadeiro como duvidoso custa mais do que deixar passar um falso, que ainda passa pelo agente de decisão e pela aprovação humana das ações de risco alto. A coluna do teste é a conferência. Com estes resultados, a regra escolhe 0,60, o limiar da skill.

Exigir também poucas janelas troca falsos pegos por verdadeiros poupados. Com todos os incidentes:

| Limiar | Condição de janelas | Falsos pegos | Verdadeiros marcados |
| --- | --- | --- | --- |
| 0,60 | nenhuma | 14 de 41 | 5 de 171 |
| 0,60 | menos de 10 | 6 de 41 | 2 de 171 |
| 0,60 | menos de 5 | 3 de 41 | 0 de 171 |
| 0,65 | nenhuma | 15 de 41 | 12 de 171 |
| 0,65 | menos de 10 | 6 de 41 | 4 de 171 |
| 0,65 | menos de 5 | 3 de 41 | 0 de 171 |

A skill fica sem a condição de janelas: ela poupa poucos verdadeiros e deixa passar boa parte dos falsos que o limiar pegaria.

Verdadeiros abaixo de 0,60, que a triagem passa a marcar como duvidosos:

| Pcap | Categoria | Confiança | Janelas |
| --- | --- | --- | --- |
| `Mirai-udpplain.pcap` | Mirai | 0,46 | 30 |
| `DoS-HTTP_Flood1.pcap` | DoS | 0,59 | 142 |
| `VulnerabilityScan.pcap` | Recon | 0,59 | 8 |
| `VulnerabilityScan.pcap` | Recon | 0,59 | 9 |
| `VulnerabilityScan.pcap` | Recon | 0,59 | 20 |

## O que o limiar não pega

23 dos 41 falsos têm confiança de 0,80 ou mais, e nenhum limiar de confiança os separa dos verdadeiros sem marcar boa parte dos ataques. Desses, 22 são de pcap de ataque com a categoria errada, com mediana de 3038 janelas.
