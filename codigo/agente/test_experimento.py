"""Testes do executor dos experimentos, com o servidor MCP de verdade (o stub, por stdio) e modelos falsos.

Os incidentes de exemplo do stub servem de conjunto: o `inc-0002` é uma força bruta (origem 198.51.100.23,
destino 192.168.137.31). Um teste monta o conjunto a partir de um pcap de mentira, como o do reprodutor.
"""

import csv
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import dpkt
import pytest

from codigo.agente.agentes import RESOLVIDO, SEM_PROPOSTA, TODAS_REJEITADAS, Perfil
from codigo.agente.experimento import (
    AVALIACAO,
    COLUNAS_DA_AVALIACAO,
    COLUNAS_DO_CUSTO,
    CUSTO,
    ERRO,
    ItemDoConjunto,
    _triagem_correta,
    consolidar,
    custo_em_dolar,
    gravar_conjunto,
    id_da_rodada,
    ler_conjunto,
    ler_rodadas,
    main,
    preparar_pcap,
    resumo,
    rodar_item,
)
from codigo.agente.test_agentes import chamada, decisao, execucao, triagem
from codigo.agente.test_laco import ProvedorFalso, resposta
from codigo.api.provedor import ErroDoProvedor
from codigo.mcp.eventos import Registro, ler
from codigo.mcp.stub import Stub
from codigo.reprodutor import avaliar
from codigo.reprodutor.test_reprodutor import (
    ATACANTE,
    VITIMA,
    benigno,
    classificador,
    escrever_pcap,
    tcp,
)

MAC_DO_TESTE = "02:00:00:00:00:01"


@pytest.fixture
def base(tmp_path):
    caminho = tmp_path / "base.jsonl"
    Stub(Registro(caminho), agente="todos").abrir_incidentes()
    return caminho


def item_de(base, verdadeiro=True, incidente="inc-0002"):
    return ItemDoConjunto(
        pcap="exemplo.pcap", incidente=incidente, categoria="BruteForce", categoria_do_pcap="BruteForce",
        verdadeiro=verdadeiro, confianca=0.9, deteccao_s=2.5, atacantes=("198.51.100.23",), log=str(base),
    )


def perfis_de(*decisao_do_modelo, triagem_do_modelo=None, incidente="inc-0002"):
    local = ProvedorFalso(*(triagem_do_modelo or triagem(incidente)), *execucao("prop-0001", "exec-0001"))
    nuvem = ProvedorFalso(*decisao_do_modelo)
    return {"local": Perfil(local, "qwen"), "nuvem": Perfil(nuvem, "claude")}


def roda(base, tmp_path, *decisao_do_modelo, verdadeiro=True, triagem_do_modelo=None, **extra):
    return rodar_item(
        item_de(base, verdadeiro), "hibrida", 1, perfis=perfis_de(*decisao_do_modelo, triagem_do_modelo=triagem_do_modelo),
        pasta_das_rodadas=tmp_path / "rodadas", **extra,
    )


# --- uma rodada ------------------------------------------------------------------------------


def test_rodada_com_proposta_aceitavel_de_risco_alto_e_medida(base, tmp_path):
    antes = len(list(ler(base)))

    medida = roda(base, tmp_path, *decisao("inc-0002", "revogar_credencial", "admin@destino-1", {}))

    assert medida["desfecho"] == RESOLVIDO and medida["erro"] is None
    assert (medida["triagem_rotulo"], medida["triagem_correta"]) == ("coerente", True)
    assert (medida["n_propostas"], medida["n_aceitaveis"], medida["primeira_aceitavel"]) == (1, 1, True)
    assert (medida["acao_primeira"], medida["papel_primeiro"]) == ("revogar_credencial", "destino")
    assert (medida["n_aprovadas"], medida["n_rejeitadas"], medida["n_baixo_risco"], medida["n_novas"]) == (1, 0, 0, 0)
    assert (medida["deteccao_s"], medida["verdadeiro"], medida["configuracao"], medida["repeticao"]) == (2.5, True, "hibrida", 1)
    por_agente = {linha["agente"]: linha for linha in medida["por_agente"]}
    assert set(por_agente) == {"triagem", "decisao", "execucao"}
    assert (por_agente["triagem"]["onde"], por_agente["decisao"]["onde"]) == ("local", "nuvem")
    assert all(linha["chamadas"] >= 1 and linha["tokens_entrada"] > 0 for linha in por_agente.values())
    assert medida["agentes_s"] >= 0
    # O log do incidente não é tocado: cada rodada trabalha numa cópia.
    assert len(list(ler(base))) == antes
    assert (tmp_path / "rodadas" / "exemplo-inc-0002-hibrida-r1.json").is_file()
    assert (tmp_path / "rodadas" / "exemplo-inc-0002-hibrida-r1.jsonl").is_file()


def test_proposta_de_risco_alto_fora_do_gabarito_e_rejeitada_e_nao_e_aceitavel(base, tmp_path):
    medida = roda(base, tmp_path, *decisao("inc-0002", "isolar_dispositivo", "destino-1", {}))

    assert medida["desfecho"] == TODAS_REJEITADAS
    assert (medida["n_propostas"], medida["n_aceitaveis"], medida["primeira_aceitavel"]) == (1, 0, False)
    assert (medida["n_aprovadas"], medida["n_rejeitadas"]) == (0, 1)


def test_proposta_de_risco_baixo_nao_passa_pelo_aprovador_mas_e_conferida(base, tmp_path):
    medida = roda(base, tmp_path, *decisao("inc-0002", "bloquear_ip", "origem-1", {"duracao": 15}))

    assert medida["desfecho"] == RESOLVIDO
    assert (medida["n_aprovadas"], medida["n_rejeitadas"], medida["n_baixo_risco"]) == (0, 0, 1)
    assert (medida["primeira_aceitavel"], medida["papel_primeiro"]) == (True, "origem")


def test_acao_nova_e_contada_e_nao_e_aceitavel(base, tmp_path):
    nova = {
        "descricao": "Ativa SYN cookies no dispositivo.", "passos": ["Ligar a opção."],
        "efeito_esperado": "O dispositivo resiste ao flood.", "como_desfazer": "Desligar a opção.",
    }

    medida = roda(base, tmp_path, *decisao("inc-0002", "ativar_syn_cookies", "destino-1", nova))

    assert (medida["n_novas"], medida["n_aceitaveis"], medida["primeira_aceitavel"]) == (1, 0, False)
    assert medida["n_rejeitadas"] == 1


def test_incidente_falso_com_triagem_duvidosa_acerta_a_triagem_e_nao_tem_acao_aceitavel(base, tmp_path):
    duvidosa = [
        chamada("obter_incidente", {"id": "inc-0002"}, "t1"),
        resposta("Incidente: inc-0002\nRótulo da triagem: duvidoso\nPor quê: confiança baixa."),
    ]
    nada = [chamada("obter_resumo", {"id": "inc-0002"}, "d1"), resposta("Nenhuma ação foi proposta.")]

    medida = roda(base, tmp_path, *nada, verdadeiro=False, triagem_do_modelo=duvidosa)

    assert medida["desfecho"] == SEM_PROPOSTA
    assert (medida["triagem_rotulo"], medida["triagem_correta"]) == ("duvidoso", True)
    assert (medida["n_propostas"], medida["primeira_aceitavel"], medida["acao_primeira"]) == (0, False, None)


def test_incidente_falso_com_proposta_aceitavel_pelo_gabarito_nao_conta_como_qualidade(base, tmp_path):
    medida = roda(base, tmp_path, *decisao("inc-0002", "bloquear_ip", "origem-1", {"duracao": 15}), verdadeiro=False)

    assert (medida["n_aceitaveis"], medida["primeira_aceitavel"]) == (1, False)
    assert medida["triagem_correta"] is False


@pytest.mark.parametrize(
    ("verdadeiro", "rotulo", "certa"),
    [
        (True, "coerente", True), (True, "duvidoso", False), (True, "ruido", False), (True, None, False),
        (False, "duvidoso", True), (False, "ruido", True), (False, "coerente", False), (False, None, False),
    ],
)
def test_a_triagem_acerta_coerente_no_verdadeiro_e_duvidoso_ou_ruido_no_falso(verdadeiro, rotulo, certa):
    assert _triagem_correta(verdadeiro, rotulo) is certa


# --- retomada e erro -------------------------------------------------------------------------


def nao_deve_rodar(*_args, **_kwargs):
    raise AssertionError("a rodada que já terminou não roda de novo")


def test_a_rodada_que_ja_terminou_nao_roda_de_novo(base, tmp_path):
    primeira = roda(base, tmp_path, *decisao("inc-0002", "bloquear_ip", "origem-1", {"duracao": 15}))

    segunda = roda(base, tmp_path, executar=nao_deve_rodar)

    assert segunda == primeira


def test_erro_do_provedor_nao_derruba_a_rodada_e_ela_roda_de_novo_na_proxima_vez(base, tmp_path):
    def falha(*_args, **_kwargs):
        raise ErroDoProvedor("o provedor caiu")

    com_erro = roda(base, tmp_path, executar=falha)

    assert com_erro["desfecho"] == ERRO and "o provedor caiu" in com_erro["erro"]
    assert (com_erro["n_propostas"], com_erro["por_agente"]) == (0, [])

    de_novo = roda(base, tmp_path, *decisao("inc-0002", "bloquear_ip", "origem-1", {"duracao": 15}))

    assert de_novo["desfecho"] == RESOLVIDO and de_novo["erro"] is None
    assert [r["desfecho"] for r in ler_rodadas(tmp_path / "rodadas")] == [RESOLVIDO]


# --- consolidar ------------------------------------------------------------------------------


def duas_rodadas(base, tmp_path):
    roda(base, tmp_path, *decisao("inc-0002", "revogar_credencial", "admin@destino-1", {}))
    rodar_item(
        item_de(base), "local", 1, pasta_das_rodadas=tmp_path / "rodadas",
        perfis={"local": Perfil(ProvedorFalso(*triagem("inc-0002"), *decisao("inc-0002", "isolar_dispositivo", "destino-1", {})), "qwen")},
    )
    return tmp_path / "rodadas"


def test_consolidar_grava_os_dois_csv_com_uma_linha_por_rodada(base, tmp_path):
    rodadas = duas_rodadas(base, tmp_path)

    lidas = consolidar(rodadas, tmp_path / "saida")

    assert len(lidas) == 2
    with open(tmp_path / "saida" / AVALIACAO, encoding="utf-8", newline="") as arquivo:
        linhas = list(csv.DictReader(arquivo))
    assert tuple(linhas[0]) == COLUNAS_DA_AVALIACAO
    assert [(c["configuracao"], c["desfecho"], c["primeira_aceitavel"]) for c in linhas] == [
        ("hibrida", RESOLVIDO, "True"), ("local", TODAS_REJEITADAS, "False"),
    ]
    with open(tmp_path / "saida" / CUSTO, encoding="utf-8", newline="") as arquivo:
        custo = list(csv.DictReader(arquivo))
    assert tuple(custo[0]) == COLUNAS_DO_CUSTO
    # Cada rodada tem uma linha por agente e uma de total, com o tempo dos agentes e o da detecção.
    assert [(c["configuracao"], c["agente"]) for c in custo if c["agente"] == "total"] == [("hibrida", "total"), ("local", "total")]
    total = next(c for c in custo if c["agente"] == "total")
    assert float(total["deteccao_s"]) == 2.5 and float(total["agentes_s"]) >= 0
    assert int(total["tokens_entrada"]) == sum(
        int(c["tokens_entrada"]) for c in custo if c["configuracao"] == "hibrida" and c["agente"] != "total"
    )


def test_o_custo_em_dolar_so_conta_o_que_rodou_na_nuvem(base, tmp_path):
    rodadas = duas_rodadas(base, tmp_path)

    consolidar(rodadas, tmp_path / "saida", preco_entrada=3.0, preco_saida=15.0)

    with open(tmp_path / "saida" / CUSTO, encoding="utf-8", newline="") as arquivo:
        custo = [c for c in csv.DictReader(arquivo) if c["configuracao"] == "hibrida"]
    decisao_ = next(c for c in custo if c["agente"] == "decisao")
    esperado = (int(decisao_["tokens_entrada"]) * 3.0 + int(decisao_["tokens_saida"]) * 15.0) / 1_000_000
    assert float(decisao_["custo_usd"]) == pytest.approx(esperado)
    assert next(c for c in custo if c["agente"] == "triagem")["custo_usd"] == ""
    assert float(next(c for c in custo if c["agente"] == "total")["custo_usd"]) == pytest.approx(esperado)


def test_custo_em_dolar_sem_preco_ou_local_e_vazio():
    nuvem = {"onde": "nuvem", "tokens_entrada": 1000, "tokens_saida": 100}
    assert custo_em_dolar(nuvem, None, 15.0) is None
    assert custo_em_dolar({**nuvem, "onde": "local"}, 3.0, 15.0) is None
    assert custo_em_dolar(nuvem, 3.0, 15.0) == pytest.approx(0.0045)


def test_o_resumo_diz_por_configuracao_as_rodadas_os_erros_a_qualidade_e_a_triagem(base, tmp_path):
    rodadas = duas_rodadas(base, tmp_path)

    linhas = resumo(ler_rodadas(rodadas))

    assert linhas == [
        # Os agentes de mentira não apontam atacante; a regra fixa acerta o do incidente de teste.
        (
            "hibrida: 1 rodadas, 0 com erro, qualidade 100.0% (1 verdadeiras), triagem certa em 100.0%, "
            "atacante certo em 0 (a regra fixa: 1)"
        ),
        (
            "local: 1 rodadas, 0 com erro, qualidade 0.0% (1 verdadeiras), triagem certa em 100.0%, "
            "atacante certo em 0 (a regra fixa: 1)"
        ),
    ]


def test_o_comando_consolidar_grava_os_csv_e_imprime_o_resumo(base, tmp_path, capsys):
    rodadas = duas_rodadas(base, tmp_path)

    codigo = main(["consolidar", "--rodadas", str(rodadas), "--saida", str(tmp_path / "saida")])

    assert codigo == 0
    assert (tmp_path / "saida" / AVALIACAO).is_file() and (tmp_path / "saida" / CUSTO).is_file()
    assert "hibrida: 1 rodadas" in capsys.readouterr().out


def test_o_comando_rodar_sem_o_ambiente_completo_para_antes_de_chamar_qualquer_coisa(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "environ", {})

    codigo = main(["rodar", "--conjunto", str(tmp_path / "nao.json"), "--env", str(tmp_path / "nao.env")])

    erro = capsys.readouterr().err
    assert codigo == 2
    assert "LLM_BASE_URL" in erro and "LLM_NUVEM_BASE_URL" not in erro


def test_o_comando_rodar_com_a_nuvem_pede_tambem_o_ambiente_da_nuvem(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "environ", {})

    codigo = main([
        "rodar", "--conjunto", str(tmp_path / "nao.json"), "--env", str(tmp_path / "nao.env"),
        "--configuracoes", "local", "hibrida",
    ])

    erro = capsys.readouterr().err
    assert codigo == 2
    assert "LLM_BASE_URL" in erro and "LLM_NUVEM_BASE_URL" in erro


def test_o_comando_rodar_de_ponta_a_ponta_por_um_gateway_http_de_mentira(base, tmp_path, monkeypatch, capsys):
    # O .env com os dois conjuntos, o Provedor HTTP, o laço, o servidor MCP, o aprovador, o JSON e o resumo.
    def tool(nome, argumentos, numero):
        chamada = {"id": f"call_{numero}", "type": "function", "function": {"name": nome, "arguments": json.dumps(argumentos)}}
        return {"role": "assistant", "content": None, "tool_calls": [chamada]}, "tool_calls"

    def texto(conteudo):
        return {"role": "assistant", "content": conteudo}, "stop"

    proposta = {"id": "inc-0002", "acao": "revogar_credencial", "alvo": "admin@destino-1", "parametros": {}, "justificativa": "A conta atacada."}
    fila = [
        tool("obter_incidente", {"id": "inc-0002"}, 1),
        texto("Incidente: inc-0002\nRótulo da triagem: coerente\nPor quê: força bruta."),
        tool("obter_resumo", {"id": "inc-0002"}, 2),
        tool("propor_acao", proposta, 3),
        texto("Veredito da triagem: aceito\nRevogar a credencial em destino-1."),
        tool("executar_acao", {"id_proposta": "prop-0001"}, 4),
        tool("verificar_efeito", {"id_execucao": "exec-0001"}, 5),
        texto("Efeito verificado: cessou."),
    ]
    pedidos = []

    class Gateway(BaseHTTPRequestHandler):
        def do_POST(self):
            pedidos.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            mensagem, motivo = fila[len(pedidos) - 1]
            corpo = json.dumps({
                "choices": [{"message": mensagem, "finish_reason": motivo}],
                "usage": {"prompt_tokens": 1000, "completion_tokens": 50},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)

        def log_message(self, *_):
            pass

    servidor = HTTPServer(("127.0.0.1", 0), Gateway)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{servidor.server_address[1]}/v1"
    ambiente = {
        "LLM_BASE_URL": url, "LLM_API_KEY": "k-local", "LLM_MODEL": "qwen",
        "LLM_NUVEM_BASE_URL": url, "LLM_NUVEM_API_KEY": "k-nuvem", "LLM_NUVEM_MODEL": "claude", "LLM_NUVEM_PROVEDORES": "anthropic",
    }
    for variavel, valor in ambiente.items():
        monkeypatch.setenv(variavel, valor)
    conjunto = gravar_conjunto([item_de(base)], tmp_path)

    try:
        codigo = main([
            "rodar", "--conjunto", str(conjunto), "--configuracoes", "hibrida", "--repeticoes", "1", "--saida", str(tmp_path),
            "--env", str(tmp_path / "nao.env"),
        ])
    finally:
        servidor.shutdown()

    assert codigo == 0
    assert "hibrida: 1 rodadas, 0 com erro, qualidade 100.0% (1 verdadeiras), triagem certa em 100.0%" in capsys.readouterr().out
    # A triagem e a execução vão ao modelo local, e só a decisão vai à nuvem, com `provider.only`.
    assert [p["model"] for p in pedidos] == ["qwen", "qwen", "claude", "claude", "claude", "qwen", "qwen", "qwen"]
    assert [("provider" in p) for p in pedidos] == [False, False, True, True, True, False, False, False]
    assert pedidos[2]["provider"] == {"only": ["anthropic"]}
    (rodada,) = ler_rodadas(tmp_path / "rodadas")
    assert (rodada["desfecho"], rodada["n_aprovadas"], rodada["primeira_aceitavel"]) == (RESOLVIDO, 1, True)
    assert sum(linha["tokens_entrada"] for linha in rodada["por_agente"]) == 8000


def test_o_comando_rodar_devolve_3_quando_alguma_rodada_deu_erro_e_a_registra(base, tmp_path, monkeypatch, capsys):
    # O provedor não responde (porta 1): a rodada dá erro, o comando diz isso e sai com 3.
    for variavel, valor in {"LLM_BASE_URL": "http://127.0.0.1:1/v1", "LLM_API_KEY": "k", "LLM_MODEL": "m"}.items():
        monkeypatch.setenv(variavel, valor)
    conjunto = gravar_conjunto([item_de(base)], tmp_path)

    codigo = main([
        "rodar", "--conjunto", str(conjunto), "--configuracoes", "local", "--repeticoes", "1", "--saida", str(tmp_path),
        "--env", str(tmp_path / "nao.env"),
    ])

    saida = capsys.readouterr()
    assert codigo == 3
    assert "local: 1 rodadas, 1 com erro" in saida.out and "1 rodadas com erro" in saida.err
    (rodada,) = ler_rodadas(tmp_path / "rodadas")
    assert rodada["desfecho"] == ERRO and "falha ao falar com o provedor" in rodada["erro"]


# --- do pcap à rodada ------------------------------------------------------------------------


def test_do_pcap_de_mentira_ao_conjunto_e_dele_a_uma_rodada_dos_agentes(tmp_path, monkeypatch):
    # Os quadros montados no teste saem do MAC 02:00:00:00:00:01; ele faz o papel do atacante.
    monkeypatch.setattr(avaliar, "ATACANTES", frozenset({MAC_DO_TESTE}))
    pcap = escrever_pcap(tmp_path / "DoS-X.pcap", [(4, lambda i: tcp(ATACANTE, VITIMA, dpkt.tcp.TH_SYN), 0.0), benigno(10)])

    itens = preparar_pcap(pcap, tmp_path / "conjunto", classificador(), categoria_do_pcap="DoS")

    (item,) = itens
    assert (item.pcap, item.incidente, item.categoria, item.verdadeiro) == ("DoS-X.pcap", "inc-0001", "DoS", True)
    # Os quadros de mentira saem todos do mesmo MAC, então os IPs benignos também contam como dele.
    assert ATACANTE in item.atacantes and item.deteccao_s == pytest.approx(2.99, abs=1e-3)
    caminho = gravar_conjunto(itens, tmp_path / "conjunto")
    (lido,) = ler_conjunto(caminho)
    assert os.path.isfile(lido.log) and os.path.isfile(lido.cenarios)
    assert lido.atacantes == item.atacantes

    local = ProvedorFalso(*triagem("inc-0001"), *execucao("prop-0001", "exec-0001"))
    nuvem = ProvedorFalso(*decisao("inc-0001", "bloquear_ip", "origem-1", {"duracao": 15}))
    medida = rodar_item(
        lido, "hibrida", 1, perfis={"local": Perfil(local, "qwen"), "nuvem": Perfil(nuvem, "claude")},
        pasta_das_rodadas=tmp_path / "rodadas",
    )

    assert medida["desfecho"] == RESOLVIDO
    assert (medida["primeira_aceitavel"], medida["papel_primeiro"], medida["triagem_correta"]) == (True, "origem", True)
    assert id_da_rodada(lido, "hibrida", 1) == "DoS-X-inc-0001-hibrida-r1"


def test_pcap_benigno_so_da_incidente_falso(tmp_path, monkeypatch):
    monkeypatch.setattr(avaliar, "ATACANTES", frozenset({MAC_DO_TESTE}))
    pcap = escrever_pcap(tmp_path / "x.pcap", [(4, lambda i: tcp(ATACANTE, VITIMA, dpkt.tcp.TH_SYN), 0.0), benigno(10)])

    (item,) = preparar_pcap(pcap, tmp_path / "conjunto", classificador(), categoria_do_pcap="Benign")

    assert item.verdadeiro is False


def test_por_pcap_limita_os_incidentes_aos_primeiros(tmp_path, monkeypatch):
    monkeypatch.setattr(avaliar, "ATACANTES", frozenset({MAC_DO_TESTE}))
    pcap = escrever_pcap(
        tmp_path / "x.pcap",
        [(4, lambda i: tcp(ATACANTE, VITIMA, dpkt.tcp.TH_SYN), 0.0), benigno(10),
         (4, lambda i: tcp(ATACANTE, VITIMA, dpkt.tcp.TH_SYN), 400.0), benigno(10)],
    )

    todos = preparar_pcap(pcap, tmp_path / "a", classificador(), categoria_do_pcap="DoS")
    primeiro = preparar_pcap(pcap, tmp_path / "b", classificador(), categoria_do_pcap="DoS", por_pcap=1)

    assert len(todos) == 2 and [i.incidente for i in primeiro] == ["inc-0001"]


def test_preparar_de_novo_recomeca_o_log_e_a_numeracao(tmp_path, monkeypatch):
    monkeypatch.setattr(avaliar, "ATACANTES", frozenset({MAC_DO_TESTE}))
    pcap = escrever_pcap(tmp_path / "x.pcap", [(4, lambda i: tcp(ATACANTE, VITIMA, dpkt.tcp.TH_SYN), 0.0), benigno(10)])

    preparar_pcap(pcap, tmp_path / "conjunto", classificador(), categoria_do_pcap="DoS")
    (de_novo,) = preparar_pcap(pcap, tmp_path / "conjunto", classificador(), categoria_do_pcap="DoS")

    assert de_novo.incidente == "inc-0001"
    abertos = [e.incidente for e in ler(tmp_path / "conjunto" / "x.jsonl") if e.tipo == "incidente_aberto"]
    assert abertos == ["inc-0001"]


def test_o_conjunto_guarda_os_caminhos_relativos_a_pasta_dele(tmp_path):
    item = ItemDoConjunto(
        pcap="a.pcap", incidente="inc-0001", categoria="DoS", categoria_do_pcap="DoS", verdadeiro=True, confianca=0.8,
        deteccao_s=1.0, atacantes=("192.0.2.1",), log="a.jsonl", cenarios="a.cenarios.json",
    )

    caminho = gravar_conjunto([item], tmp_path)
    corpo = json.loads(caminho.read_text(encoding="utf-8"))

    assert (corpo["itens"][0]["log"], corpo["itens"][0]["cenarios"]) == ("a.jsonl", "a.cenarios.json")
    (lido,) = ler_conjunto(caminho)
    assert lido.log == str(tmp_path / "a.jsonl") and lido.cenarios == str(tmp_path / "a.cenarios.json")
