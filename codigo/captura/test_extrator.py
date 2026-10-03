

from codigo.captura.extrator import COLUNAS

CABECALHO_OFICIAL = (
    "Header_Length,Protocol Type,Time_To_Live,Rate,fin_flag_number,syn_flag_number,"
    "rst_flag_number,psh_flag_number,ack_flag_number,ece_flag_number,cwr_flag_number,"
    "ack_count,syn_count,fin_count,rst_count,HTTP,HTTPS,DNS,Telnet,SMTP,SSH,IRC,TCP,UDP,"
    "DHCP,ARP,ICMP,IGMP,IPv,LLC,Tot sum,Min,Max,AVG,Std,Tot size,IAT,Number,Variance"
)


def test_colunas_na_ordem_do_csv_oficial():
    assert len(COLUNAS) == 39
    assert ",".join(COLUNAS) == CABECALHO_OFICIAL
