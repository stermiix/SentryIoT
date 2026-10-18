# Mirai - Botnet IoT

- **Definição:** Família de malware que compromete dispositivos IoT e os integra a uma botnet, permitindo sua utilização em ataques distribuídos.
- **Objetivo:** Estabelecer uma botnet para disparar ataques em larga escala e encaminhar tráfego encapsulado.

## Mitigações recomendadas

| Mitigações Recomendadas | Fonte |
| --- | --- |
| Filtrar ou limitar tráfego GRE e UDP abusivo caracterizado no incidente, preservando o tráfego legítimo. | [MITRE ATT&CK — T1498](https://attack.mitre.org/techniques/T1498/) |
| Segmentar ou colocar em quarentena dispositivos suspeitos após corroboração do comprometimento e avaliação de dependências. | [MITRE ATT&CK — M1030](https://attack.mitre.org/mitigations/M1030/) |
| Substituir credenciais padrão e proteger o acesso às interfaces administrativas de dispositivos IoT. | [NIST — IR 8259A](https://csrc.nist.gov/pubs/ir/8259/a/final) |
| Desabilitar serviços e interfaces de rede desnecessários, incluindo administração remota insegura quando dispensável. | [NIST — IR 8259A](https://csrc.nist.gov/pubs/ir/8259/a/final) |
| Atualizar software/firmware e recuperar o dispositivo por procedimento confiável quando houver comprometimento confirmado. | [NIST — IR 8259A](https://csrc.nist.gov/pubs/ir/8259/a/final) |
