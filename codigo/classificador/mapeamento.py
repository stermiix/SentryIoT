"""Rótulos do CICIoT2023 e o agrupamento em categorias.

O dataset tem 34 classes: 33 ataques e o tráfego benigno (Neto et al., 2023). Os autores agrupam
os ataques em sete categorias, e com o tráfego benigno são oito. O agrupamento abaixo foi
conferido com a tabela de ataques do artigo, reproduzida no `README.pdf` do dataset, e com os
dicionários `dict_7classes` e `dict_2classes` do notebook dos autores (`example.ipynb`).

A grafia canônica é a dos dicionários dos autores. Os arquivos trazem outras: o `MERGED_CSV`
escreve tudo em maiúsculas e chama o tráfego benigno de `BENIGN`, e a pasta dos CSVs por ataque
se chama `Benign_Final`. Por isso todo rótulo lido de arquivo passa por `normalizar`.
"""

# Categoria e os rótulos que ela reúne, na ordem da tabela de ataques do artigo.
GRUPOS = (
    ("DDoS", (
        "DDoS-ACK_Fragmentation", "DDoS-UDP_Flood", "DDoS-SlowLoris", "DDoS-ICMP_Flood",
        "DDoS-RSTFINFlood", "DDoS-PSHACK_Flood", "DDoS-HTTP_Flood", "DDoS-UDP_Fragmentation",
        "DDoS-ICMP_Fragmentation", "DDoS-TCP_Flood", "DDoS-SYN_Flood", "DDoS-SynonymousIP_Flood",
    )),
    ("DoS", ("DoS-TCP_Flood", "DoS-HTTP_Flood", "DoS-SYN_Flood", "DoS-UDP_Flood")),
    ("Mirai", ("Mirai-greip_flood", "Mirai-greeth_flood", "Mirai-udpplain")),
    ("Recon", (
        "Recon-PingSweep", "Recon-OSScan", "VulnerabilityScan", "Recon-PortScan", "Recon-HostDiscovery",
    )),
    ("Spoofing", ("MITM-ArpSpoofing", "DNS_Spoofing")),
    ("Web", (
        "SqlInjection", "CommandInjection", "Backdoor_Malware", "Uploading_Attack", "XSS",
        "BrowserHijacking",
    )),
    ("BruteForce", ("DictionaryBruteForce",)),
    ("Benign", ("BenignTraffic",)),
)
CATEGORIAS = tuple(nome for nome, _ in GRUPOS)
ROTULOS = tuple(rotulo for _, rotulos in GRUPOS for rotulo in rotulos)
CATEGORIA_DO_ROTULO = {rotulo: nome for nome, rotulos in GRUPOS for rotulo in rotulos}
BINARIO_DO_ROTULO = {
    rotulo: "Benign" if nome == "Benign" else "Attack" for rotulo, nome in CATEGORIA_DO_ROTULO.items()
}

# Nomes do tráfego benigno fora do dicionário dos autores: no MERGED_CSV e na pasta por ataque.
_OUTROS_NOMES = {"benign": "BenignTraffic", "benign_final": "BenignTraffic"}
_CANONICO = {rotulo.casefold(): rotulo for rotulo in ROTULOS} | _OUTROS_NOMES


def normalizar(rotulo):
    """Devolve o rótulo na grafia canônica, qualquer que seja a caixa das letras.

    Rótulo fora das 34 classes levanta ValueError. Devolver o texto como veio faria o
    agrupamento não casar com nada mais adiante, sem aviso.
    """
    canonico = _CANONICO.get(rotulo.strip().casefold()) if isinstance(rotulo, str) else None
    if canonico is None:
        raise ValueError(f"rótulo desconhecido: {rotulo!r}")
    return canonico


def categoria(rotulo):
    """Categoria do rótulo, entre as 8 de CATEGORIAS."""
    return CATEGORIA_DO_ROTULO[normalizar(rotulo)]


def binario(rotulo):
    """"Attack" ou "Benign", como no `dict_2classes` dos autores."""
    return BINARIO_DO_ROTULO[normalizar(rotulo)]
