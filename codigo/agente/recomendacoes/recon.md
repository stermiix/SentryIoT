# Recon - Reconhecimento

Categorias: Recon

- **Definição:** Varredura sistemática e automatizada de endereçamento IP e portas lógicas na rede.
- **Objetivo:** Coletar informações como hosts, portas, sistemas operacionais, serviços e vulnerabilidades, de modo a identificar possíveis alvos ou pontos de entrada.

## Mitigações recomendadas

| Mitigações Recomendadas | Ação do catálogo | Fonte |
| --- | --- | --- |
| Fechar portas e desativar serviços sem necessidade operacional, reduzindo a superfície exposta. | nenhuma | [MITRE ATT&CK — T1046](https://attack.mitre.org/techniques/T1046/) |
| Segmentar redes IoT e restringir o alcance de hosts e serviços sensíveis por controles de acesso. | nenhuma | [MITRE ATT&CK — T1046](https://attack.mitre.org/techniques/T1046/) |
| Utilizar IDS/IPS para identificar e, quando apropriado, interromper varreduras de portas e serviços. | `bloquear_ip` | [MITRE ATT&CK — T1046](https://attack.mitre.org/techniques/T1046/) |
| Restringir varreduras não autorizadas após diferenciar atividade maliciosa de inventário ou teste autorizado. | `limitar_taxa` | [MITRE ATT&CK — T1046](https://attack.mitre.org/techniques/T1046/) |
