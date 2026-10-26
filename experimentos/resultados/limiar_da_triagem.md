# Limiar de confiança da triagem

Gerado por `python -m codigo.reprodutor.limiar`, a partir dos resultados da avaliação dos 38 pcaps (`python -m codigo.reprodutor.avaliar`, relatório em `reproducao_dos_pcaps.md`).

A regra testada é a da skill de triagem: o incidente com confiança do classificador abaixo do limiar recebe o veredito "duvidoso". Um incidente é verdadeiro quando o pcap não é benigno, quando alguma janela dele tem quadro de um atacante do dataset e quando a categoria do incidente é a do pcap. Os outros são falsos.

São 235 incidentes: 178 verdadeiros e 57 falsos. 126 ficam inteiros fora do trecho de teste do modelo, e 109 têm janela no teste.

Dos 57 falsos, 4 são alarmes em pcap benigno e 53 são incidentes de um pcap de ataque com a categoria errada. Para a triagem, os dois pedem o veredito duvidoso: no segundo caso o ataque existe, mas a categoria que guia a resposta está errada.

Cada par de colunas diz quantos incidentes ficam abaixo do limiar: falsos pegos e verdadeiros marcados.

| Limiar | Falsos, todos | Verdadeiros, todos | Falsos, fora do teste | Verdadeiros, fora do teste | Falsos, no teste | Verdadeiros, no teste |
| --- | --- | --- | --- | --- | --- | --- |
| 0,50 | 15 de 57 | 2 de 178 | 1 de 16 | 0 de 110 | 14 de 41 | 2 de 68 |
| 0,55 | 19 de 57 | 2 de 178 | 1 de 16 | 0 de 110 | 18 de 41 | 2 de 68 |
| 0,60 (escolhido) | 24 de 57 | 4 de 178 | 3 de 16 | 0 de 110 | 21 de 41 | 4 de 68 |
| 0,65 | 27 de 57 | 15 de 178 | 3 de 16 | 0 de 110 | 24 de 41 | 15 de 68 |
| 0,70 | 28 de 57 | 20 de 178 | 3 de 16 | 2 de 110 | 25 de 41 | 18 de 68 |
| 0,75 | 31 de 57 | 31 de 178 | 4 de 16 | 8 de 110 | 27 de 41 | 23 de 68 |
| 0,80 | 32 de 57 | 44 de 178 | 4 de 16 | 17 de 110 | 28 de 41 | 27 de 68 |

## A escolha

O limiar é escolhido só com os incidentes fora do teste: é o menor dos limiares que pegam ali o máximo de falsos sem marcar nenhum verdadeiro. O empate é resolvido para baixo porque marcar um ataque verdadeiro como duvidoso custa mais do que deixar passar um falso, que ainda passa pelo agente de decisão e pela aprovação humana das ações de risco alto. A coluna do teste é a conferência. Com estes resultados, a regra escolhe 0,60, o limiar da skill.

Exigir também poucas janelas troca falsos pegos por verdadeiros poupados. Com todos os incidentes:

| Limiar | Condição de janelas | Falsos pegos | Verdadeiros marcados |
| --- | --- | --- | --- |
| 0,60 | nenhuma | 24 de 57 | 4 de 178 |
| 0,60 | menos de 10 | 13 de 57 | 2 de 178 |
| 0,60 | menos de 5 | 8 de 57 | 0 de 178 |
| 0,65 | nenhuma | 27 de 57 | 15 de 178 |
| 0,65 | menos de 10 | 15 de 57 | 2 de 178 |
| 0,65 | menos de 5 | 10 de 57 | 0 de 178 |

A skill fica sem a condição de janelas: ela poupa poucos verdadeiros e deixa passar boa parte dos falsos que o limiar pegaria.

Verdadeiros abaixo de 0,60, que a triagem passa a marcar como duvidosos:

| Pcap | Categoria | Confiança | Janelas |
| --- | --- | --- | --- |
| `Mirai-udpplain.pcap` | Mirai | 0,46 | 27 |
| `VulnerabilityScan.pcap` | Recon | 0,47 | 7 |
| `VulnerabilityScan.pcap` | Recon | 0,55 | 7 |
| `DoS-HTTP_Flood1.pcap` | DoS | 0,59 | 142 |

## O que o limiar não pega

25 dos 57 falsos têm confiança de 0,80 ou mais, e nenhum limiar de confiança os separa dos verdadeiros sem marcar boa parte dos ataques. Desses, 24 são de pcap de ataque com a categoria errada, com mediana de 3298 janelas.
