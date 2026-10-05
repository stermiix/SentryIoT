# Alerta duvidoso: quando o tráfego pode ser legítimo

## Sinais de falso positivo

Alguns sinais indicam que o tráfego apontado como ataque pode ser legítimo: confiança baixa do
classificador, uma só origem que é um dispositivo conhecido da rede, quadros grandes em uma
conexão já estabelecida e um destino habitual para esse dispositivo. Atualização de firmware,
cópia de segurança e transmissão de vídeo produzem esse tipo de tráfego.

## Preferir medida reversível e de risco baixo, ou nenhuma

Quando o alerta é duvidoso, não convém aplicar medida de risco alto. Se alguma medida for
necessária, limitar a taxa por prazo curto afeta menos o serviço do que bloquear ou isolar,
caso o tráfego seja legítimo. Registrar a dúvida na recomendação ajuda a pessoa que vai revisar
o incidente.
