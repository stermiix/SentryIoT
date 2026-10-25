# Custo do modelo do sistema na operação

Gerado por `python -m codigo.reprodutor.custo` em 2026-10-25T18:48:29-03:00, a partir de `manifesto_custo_do_modelo_do_sistema.json`.

**O que foi feito.** O modelo do sistema (`rf_regerado_janela_100.joblib`) foi medido num núcleo, como o reprodutor o usa, com as funções da rodada i de `rodadas_de_teste.md`. A latência é de uma janela isolada, em 2.214 janelas diferentes do trecho de teste de 8 pcaps, um por categoria, depois de uma de aquecimento; a segunda linha de latência inclui a montagem da matriz a partir da linha do extrator. O modelo foi lido num processo novo, três vezes, para medir o tempo e a memória. A vazão do extrator é a de janela de 100 com os endereços, lendo o pcap inteiro, e a do reprodutor soma a classificação em lotes e a política de acionamento. Máquina: Apple M5, 16 GB de memória, macOS-27.0.1-arm64-arm-64bit. Os tempos mudam de uma execução para outra.

| Medida | Valor |
|---|---|
| Arquivo do modelo | 365,6 MB, 3.046.126 nós, profundidade média 48,1 e máxima 56 |
| Importar o scikit-learn e o joblib, num processo novo | 0,66 s |
| Ler o modelo | 0,14 s, com o arquivo no cache do sistema |
| Memória do processo | 158 MB antes de ler o modelo e 896 MB depois |
| Pico de memória do processo da medida | 910 MB |
| Uma janela, `predict_proba`, um núcleo | mediana 1,67 ms, p95 1,79 ms, p99 1,86 ms |
| Uma janela, da linha do extrator à probabilidade | mediana 1,68 ms, p95 1,79 ms, p99 1,84 ms |
| Lote de 1.000 janelas | 8,6 ms |
| Extrator de janela de 100 em `Recon-PortScan.pcap` | 831.856 quadros em 5,5 s: 150.923 quadros/s e 1.493 janelas/s |
| Reprodutor inteiro em `Recon-PortScan.pcap` | 831.856 quadros em 5,8 s: 142.821 quadros/s e 1.412 janelas/s |

Janelas da latência por pcap: `BenignTraffic2.pcap` 300; `DDoS-SYN_Flood1.pcap` 300; `DoS-SYN_Flood1.pcap` 300; `Mirai-greip_flood21.pcap` 300; `Recon-PortScan.pcap` 300; `DNS_Spoofing.pcap` 300; `XSS.pcap` 114; `DictionaryBruteForce.pcap` 300.
