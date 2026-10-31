# O modelo do sistema fora do CICIoT2023, e as regras de alarme comparadas

Gerado por `python -m codigo.reprodutor.regras` em 29/10/2026, com Python 3.11.2 e scikit-learn 1.9.1. O modelo é o de 13/10 (`modelos/rf_regerado_janela_100.joblib`), sem retreino. A descrição das capturas e do método está no topo de `codigo/reprodutor/regras.py`; os pcaps, com tamanho e SHA-256, no manifesto ao lado.

Como ler: numa captura benigna, todo incidente é falso. Numa de ataque, sem rótulo por janela, conta se o sistema abriu incidente, em quanto tempo e em que categoria. Janela que leva mais de 60 s para fechar não é julgada (`DURACAO_MAXIMA_S`). Nos floods grandes, só o começo foi lido. A casa entra só com números agregados.

## A regra do sistema (sistema: argmax e 4 seguidas), captura por captura

| Grupo | Captura | Horas | Janelas | Não julgadas | Ataque nas julgadas | Incidentes | Categoria do 1º | 1º alarme (s) |
|---|---|---|---|---|---|---|---|---|
| Casa | casa (IoT de uma residência) | 1,5 | 243 | 29 | 29,0% | 0 | — | — |
| CICIoT2023 benigno (teste) | BenignTraffic2 | 8,0 | 31.031 | 0 | 0,9% | 1 | DDoS+DoS | 20395,5 |
| IoT-23 benigno | hue_4-1 | 21,8 | 216 | 215 | 0,0% | 0 | — | — |
| IoT-23 benigno | echo_5-1 | 5,5 | 3.972 | 100 | 0,9% | 1 | Spoofing | 2781,2 |
| IoT-23 benigno | somfy_7-1_01 | 1,4 | 68 | 64 | 25,0% | 0 | — | — |
| IoT-23 benigno | somfy_7-1_02 | 24,0 | 1.196 | 1.175 | 0,0% | 0 | — | — |
| IoT-23 benigno | somfy_7-1_03 | 12,3 | 628 | 592 | 0,0% | 0 | — | — |
| IoT-23 benigno | somfy_7-1_04 | 24,0 | 1.215 | 1.156 | 0,0% | 0 | — | — |
| IoT-23 benigno | somfy_7-1_05 | 24,0 | 1.215 | 1.160 | 0,0% | 0 | — | — |
| IoT-23 benigno | somfy_7-1_06 | 24,0 | 1.191 | 1.173 | 0,0% | 0 | — | — |
| CICIoMT2024 benigno | Benign_test | 3,9 | 3.760 | 0 | 75,7% | 4 | DDoS+DoS | 22,9 |
| CICIoT2023 ataque (teste) | DNS_Spoofing | 4,3 | 5.365 | 15 | 64,7% | 16 | Spoofing | 12,8 |
| CICIoT2023 ataque (teste) | MITM-ArpSpoofing | 4,4 | 7.428 | 21 | 50,6% | 11 | Spoofing | 10,3 |
| CICIoT2023 ataque (teste) | Recon-PortScan | 2,5 | 2.467 | 11 | 30,8% | 7 | Recon | 151,8 |
| CICIoT2023 ataque (teste) | Recon-OSScan | 3,7 | 2.946 | 15 | 33,3% | 7 | Recon | 1,4 |
| CICIoT2023 ataque (teste) | Recon-HostDiscovery | 2,4 | 4.030 | 0 | 87,1% | 2 | Recon | 2,0 |
| CICIoT2023 ataque (teste) | Recon-PingSweep | 0,0 | 67 | 0 | 0,0% | 0 | — | — |
| CICIoT2023 ataque (teste) | VulnerabilityScan | 5,8 | 11.199 | 0 | 13,4% | 18 | Recon | 105,6 |
| CICIoT2023 ataque (teste) | DictionaryBruteForce | 1,3 | 391 | 2 | 60,4% | 5 | BruteForce | 5,1 |
| CICIoT2023 ataque (teste) | SqlInjection | 0,1 | 156 | 0 | 21,2% | 1 | DDoS+DoS | 90,4 |
| CICIoT2023 ataque (teste) | XSS | 0,1 | 114 | 2 | 72,3% | 1 | Web | 16,3 |
| CICIoT2023 ataque (teste) | CommandInjection | 0,1 | 161 | 1 | 39,4% | 1 | Web | 132,7 |
| CICIoT2023 ataque (teste) | BrowserHijacking | 0,0 | 175 | 0 | 12,6% | 1 | Recon | 120,8 |
| CICIoT2023 ataque (teste) | Backdoor_Malware | 0,1 | 96 | 0 | 64,6% | 1 | Web | 16,5 |
| CICIoT2023 ataque (teste) | Uploading_Attack | 0,0 | 37 | 0 | 73,0% | 1 | Web | 12,3 |
| CICIoMT2024 ataque | ARP_Spoofing_test | 0,1 | 174 | 0 | 74,1% | 1 | Spoofing | 3,4 |
| CICIoMT2024 ataque | Recon-OS_Scan_test | 0,1 | 383 | 0 | 99,5% | 1 | Recon | 0,1 |
| CICIoMT2024 ataque | Recon-Ping_Sweep_test | 0,0 | 18 | 0 | 100,0% | 1 | Recon | 2,8 |
| CICIoMT2024 ataque | Recon-Port_Scan_test | 0,0 | 2.262 | 0 | 98,3% | 2 | Recon | 0,0 |
| CICIoMT2024 ataque | Recon-VulScan_test | 0,1 | 103 | 0 | 82,5% | 2 | DDoS+DoS | 29,7 |
| CICIoMT2024 ataque | MQTT-Malformed_Data_test | 0,1 | 174 | 0 | 50,6% | 1 | DDoS+DoS | 53,8 |
| CICIoMT2024 ataque | MQTT-DDoS-Connect_Flood_test | 0,0 | 3.000 | 0 | 100,0% | 1 | DDoS+DoS | 0,0 |
| CICIoMT2024 ataque | MQTT-DDoS-Publish_Flood_test | 0,0 | 2.999 | 0 | 99,8% | 1 | DDoS+DoS | 0,1 |
| CICIoMT2024 ataque | MQTT-DoS-Connect_Flood_test | 0,1 | 2.999 | 0 | 100,0% | 1 | DDoS+DoS | 0,3 |
| CICIoMT2024 ataque | MQTT-DoS-Publish_Flood_test | 0,0 | 2.999 | 0 | 100,0% | 1 | DDoS+DoS | 0,1 |
| CICIoMT2024 ataque | TCP_IP-DoS-SYN_test | 0,0 | 2.999 | 0 | 100,0% | 1 | DDoS+DoS | 0,0 |
| CICIoMT2024 ataque | TCP_IP-DoS-TCP_test | 0,0 | 2.999 | 0 | 99,6% | 1 | DDoS+DoS | 0,0 |
| CICIoMT2024 ataque | TCP_IP-DoS-UDP_test | 0,0 | 2.999 | 0 | 99,8% | 1 | DDoS+DoS | 0,0 |
| CICIoMT2024 ataque | TCP_IP-DoS-ICMP_test | 0,0 | 2.999 | 0 | 100,0% | 1 | DDoS+DoS | 0,0 |
| CICIoMT2024 ataque | TCP_IP-DDoS-SYN_test | 0,0 | 2.999 | 0 | 100,0% | 1 | DDoS+DoS | 0,0 |
| CICIoMT2024 ataque | TCP_IP-DDoS-TCP_test | 0,0 | 3.000 | 0 | 100,0% | 1 | DDoS+DoS | 0,0 |
| CICIoMT2024 ataque | TCP_IP-DDoS-UDP1_test | 0,0 | 2.999 | 0 | 100,0% | 1 | DDoS+DoS | 0,0 |
| CICIoMT2024 ataque | TCP_IP-DDoS-ICMP1_test | 0,0 | 3.000 | 0 | 100,0% | 1 | DDoS+DoS | 0,0 |
| IoT-23 malware ativo | malware_34-1 | 24,0 | 2.338 | 337 | 60,9% | 11 | DDoS+DoS | 41,5 |
| IoT-23 malware ativo | malware_42-1 | 8,1 | 244 | 44 | 98,5% | 4 | DDoS+DoS | 11,8 |
| IoT-23 malware ativo | malware_3-1 | 36,1 | 4.969 | 337 | 86,9% | 30 | DDoS+DoS | 1168,2 |
| IoT-23 malware ativo | malware_9-1 | 4,6 | 50 | 16 | 100,0% | 1 | DDoS+DoS | 16503,3 |
| IoT-23 malware ativo | malware_1-1 | 111,9 | 16.862 | 0 | 100,0% | 1 | DDoS+DoS | 98,0 |
| IoT-23 malware ativo | malware_7-1 | 3,8 | 20.000 | 3 | 100,0% | 1 | DDoS+DoS | 656,5 |
| IoT-23 malware ativo | malware_36-1 | 3,5 | 20.000 | 0 | 100,0% | 1 | DDoS+DoS | 7,6 |
| IoT-23 malware ativo | malware_48-1 | 1,4 | 20.000 | 0 | 100,0% | 1 | DDoS+DoS | 2,2 |
| IoT-23 malware silencioso | malware_20-1 | 24,0 | 501 | 501 | — | 0 | — | — |
| IoT-23 malware silencioso | malware_21-1 | 24,0 | 502 | 502 | — | 0 | — | — |
| IoT-23 malware silencioso | malware_8-1 | 24,0 | 236 | 236 | — | 0 | — | — |

## As regras comparadas

Incidentes falsos por grupo benigno e no total; capturas de ataque com alarme. O malware silencioso do IoT-23 fica fora do total: nenhuma regra julga as janelas dele.

| Regra | Casa (1,5 h) | CICIoT2023 benigno (teste) (8,0 h) | CICIoMT2024 benigno (3,9 h) | IoT-23 benigno (137,0 h) | Falsos no total | CICIoT2023 ataque (teste) | CICIoMT2024 ataque | IoT-23 malware ativo | Com alarme | Categoria certa no CICIoT2023 | Atraso mediano, CICIoT2023 / IoT-23 (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| sistema: argmax e 4 seguidas | 0 | 1 | 4 | 1 | 6 | 13/14 | 18/18 | 8/8 | 39/40 | 11/14 | 16,3 / 69,8 |
| argmax e 3 seguidas | 4 | 4 | 5 | 1 | 14 | 13/14 | 18/18 | 8/8 | 39/40 | 10/14 | 11,9 / 57,0 |
| argmax e 5 seguidas | 0 | 0 | 3 | 1 | 4 | 12/14 | 18/18 | 8/8 | 38/40 | 11/14 | 24,9 / 82,6 |
| limiar de 0,60 e 3 seguidas | 2 | 8 | 6 | 1 | 17 | 13/14 | 18/18 | 8/8 | 39/40 | 11/14 | 11,9 / 57,0 |
| limiar de 0,65 e 3 seguidas | 0 | 5 | 5 | 1 | 11 | 13/14 | 18/18 | 8/8 | 39/40 | 10/14 | 11,9 / 57,0 |
| limiar de 0,70 e 3 seguidas | 0 | 2 | 2 | 1 | 5 | 12/14 | 18/18 | 8/8 | 38/40 | 10/14 | 13,2 / 57,0 |
| limiar de 0,75 e 3 seguidas | 0 | 0 | 2 | 1 | 3 | 12/14 | 18/18 | 8/8 | 38/40 | 10/14 | 18,1 / 58,2 |
| limiar de 0,80 e 3 seguidas | 0 | 0 | 2 | 1 | 3 | 12/14 | 18/18 | 8/8 | 38/40 | 10/14 | 24,9 / 58,2 |
| limiar de 0,65 e 4 seguidas | 0 | 1 | 3 | 1 | 5 | 13/14 | 18/18 | 8/8 | 39/40 | 11/14 | 16,3 / 69,8 |
| limiar de 0,70 e 4 seguidas | 0 | 0 | 2 | 1 | 3 | 12/14 | 18/18 | 8/8 | 38/40 | 10/14 | 16,4 / 69,8 |
| Spoofing com 0,80, demais argmax e 3 seguidas | 0 | 4 | 2 | 1 | 7 | 13/14 | 18/18 | 8/8 | 39/40 | 10/14 | 13,5 / 57,0 |
| Spoofing e DDoS+DoS com 0,80, demais argmax e 3 seguidas | 0 | 2 | 2 | 1 | 5 | 13/14 | 18/18 | 8/8 | 39/40 | 10/14 | 13,5 / 58,2 |

## Por janela, no teste publicado do CICIoT2023

O número de janelas seguidas não muda a classificação de cada janela: as regras que só diferem nele têm a mesma linha.

| Regra de janela | Benigno como ataque | Ataque como benigno | Macro-F1 | Recall Spoofing | Recall Recon | Recall Web | Recall BruteForce |
|---|---|---|---|---|---|---|---|
| argmax | 0,94% | 3,52% | 75,7% | 80,1% | 54,9% | 35,7% | 34,8% |
| limiar de 0,60 | 1,11% | 3,80% | 74,4% | 73,8% | 50,7% | 37,6% | 35,2% |
| limiar de 0,65 | 0,84% | 4,31% | 72,9% | 66,9% | 48,2% | 35,3% | 34,1% |
| limiar de 0,70 | 0,54% | 4,93% | 70,7% | 57,9% | 46,3% | 31,4% | 31,9% |
| limiar de 0,75 | 0,36% | 5,70% | 68,1% | 46,9% | 44,5% | 27,5% | 30,8% |
| limiar de 0,80 | 0,22% | 6,52% | 65,0% | 34,9% | 42,5% | 23,9% | 29,3% |
| Spoofing com 0,80, demais argmax | 0,94% | 4,75% | 69,6% | 34,9% | 54,9% | 35,7% | 34,8% |
| Spoofing e DDoS+DoS com 0,80, demais argmax | 0,63% | 5,74% | 69,0% | 34,9% | 54,9% | 35,7% | 34,8% |

## Reproduzir

- Comando: `python -m codigo.reprodutor.regras`, a partir da raiz do repositório.
- Duração desta execução: 5,5 min.
