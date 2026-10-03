"""Extrator de features do SentryIoT.

Transforma quadros Ethernet nas 39 features do CICIoT2023 (Neto et al., 2023). Cada linha
resume uma janela de quadros IPv4 ou ARP consecutivos. As regras de medição seguem o que o
código publicado pelos autores do dataset faz, para que o classificador receba em operação
os mesmos números com que foi treinado.

Uso, a partir da raiz do repositório:
    python -m codigo.captura.extrator entrada.pcap saida.csv
"""


# Nome da coluna e bit correspondente no campo de flags do TCP.
FLAGS = (
    ("fin_flag_number", 0x01),
    ("syn_flag_number", 0x02),
    ("rst_flag_number", 0x04),
    ("psh_flag_number", 0x08),
    ("ack_flag_number", 0x10),
    ("ece_flag_number", 0x40),
    ("cwr_flag_number", 0x80),
)
# Indicador e porta TCP que o ativa. "IRC" olha a porta 21 porque é assim no código dos autores.
PORTAS_TCP = (("HTTP", 80), ("HTTPS", 443), ("Telnet", 23), ("SMTP", 25), ("SSH", 22), ("IRC", 21))
INDICADORES = (
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP", "DHCP",
    "ARP", "ICMP", "IGMP", "IPv", "LLC",
)
# Coluna de contagem e flag que ela soma dentro da janela.
CONTAGENS = (
    ("ack_count", "ack_flag_number"),
    ("syn_count", "syn_flag_number"),
    ("fin_count", "fin_flag_number"),
    ("rst_count", "rst_flag_number"),
)
COLUNAS = (
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
    *(nome for nome, _ in FLAGS),
    *(nome for nome, _ in CONTAGENS),
    *INDICADORES,
    "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number", "Variance",
)
# Colunas que a janela resume pela média dos quadros.
MEDIAS = (
    "Header_Length", "Time_To_Live", *(nome for nome, _ in FLAGS), *INDICADORES, "Tot size", "IAT",
)
