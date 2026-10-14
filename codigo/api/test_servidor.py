"""Testes das rotas do servidor, chamando o app ASGI direto, sem rede e sem o provedor."""

import asyncio
import json

import pytest

from codigo.api.configuracao import Configuracao
from codigo.api.provedor import ErroDoProvedor, RespostaDoProvedor
from codigo.api.servidor import criar_app

CONFIG = Configuracao(url_base="https://g/v1", chave="k", modelo="m-padrao")


def chamar(app, metodo, caminho, corpo=None, bruto=None):
    """Uma requisição HTTP ao app ASGI. Devolve (status, json ou texto)."""
    status, _, texto = chamar_bruto(app, metodo, caminho, corpo, bruto)
    try:
        return status, json.loads(texto)
    except json.JSONDecodeError:
        return status, texto


def chamar_bruto(app, metodo, caminho, corpo=None, bruto=None):
    """Como `chamar`, mas devolve (status, cabeçalhos, texto do corpo)."""
    dados = bruto if bruto is not None else (json.dumps(corpo).encode("utf-8") if corpo is not None else b"")
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": metodo, "scheme": "http",
        "path": caminho, "raw_path": caminho.encode(), "root_path": "", "query_string": b"",
        "headers": [(b"host", b"teste"), (b"content-type", b"application/json"), (b"content-length", str(len(dados)).encode())],
        "client": ("127.0.0.1", 1), "server": ("teste", 80),
    }
    mensagens = iter([{"type": "http.request", "body": dados, "more_body": False}])
    recebido = {"status": None, "cabecalhos": {}, "corpo": b""}

    async def receive():
        return next(mensagens, {"type": "http.disconnect"})

    async def send(mensagem):
        if mensagem["type"] == "http.response.start":
            recebido["status"] = mensagem["status"]
            recebido["cabecalhos"] = {k.decode().lower(): v.decode() for k, v in mensagem.get("headers", [])}
        elif mensagem["type"] == "http.response.body":
            recebido["corpo"] += mensagem.get("body", b"")

    asyncio.run(app(scope, receive, send))
    return recebido["status"], recebido["cabecalhos"], recebido["corpo"].decode("utf-8")


def provedor_que_responde(registro, conteudo="Resposta.", tokens=(10, 2)):
    def chamar_provedor(modelo, sistema, mensagens):
        registro.append((modelo, sistema, mensagens))
        return RespostaDoProvedor(conteudo=conteudo, modelo=modelo, tokens_entrada=tokens[0], tokens_saida=tokens[1])

    return chamar_provedor


PEDIDO = {"modelo": "m-padrao", "sistema": "Seja breve.", "mensagens": [{"papel": "usuario", "conteudo": "Oi"}]}


def test_chat_devolve_conteudo_modelo_tokens_e_tempo():
    registro = []
    app = criar_app(CONFIG, provedor_que_responde(registro))

    status, corpo = chamar(app, "POST", "/api/chat", PEDIDO)

    assert status == 200
    assert corpo["conteudo"] == "Resposta."
    assert corpo["modelo"] == "m-padrao"
    assert (corpo["tokens_entrada"], corpo["tokens_saida"]) == (10, 2)
    assert isinstance(corpo["tempo_ms"], int) and corpo["tempo_ms"] >= 0
    assert registro == [("m-padrao", "Seja breve.", [{"papel": "usuario", "conteudo": "Oi"}])]


def test_modelo_vazio_ou_ausente_usa_o_modelo_da_configuracao():
    registro = []
    app = criar_app(CONFIG, provedor_que_responde(registro))

    status, corpo = chamar(app, "POST", "/api/chat", {"sistema": "", "mensagens": [{"papel": "usuario", "conteudo": "Oi"}]})

    assert status == 200
    assert corpo["modelo"] == "m-padrao"
    assert registro[0][0] == "m-padrao"


def test_tokens_nulos_quando_o_provedor_nao_informa():
    app = criar_app(CONFIG, provedor_que_responde([], tokens=(None, None)))

    status, corpo = chamar(app, "POST", "/api/chat", PEDIDO)

    assert status == 200
    assert (corpo["tokens_entrada"], corpo["tokens_saida"]) == (None, None)


def test_resposta_sem_texto_vem_com_conteudo_vazio():
    app = criar_app(CONFIG, provedor_que_responde([], conteudo=""))

    status, corpo = chamar(app, "POST", "/api/chat", PEDIDO)

    assert (status, corpo["conteudo"]) == (200, "")


@pytest.mark.parametrize("codigo", [429, 500, None])
def test_erro_do_provedor_vira_502_com_a_mensagem_e_o_codigo(codigo):
    def chamar_provedor(modelo, sistema, mensagens):
        raise ErroDoProvedor("o provedor recusou", codigo=codigo)

    app = criar_app(CONFIG, chamar_provedor)

    status, corpo = chamar(app, "POST", "/api/chat", PEDIDO)

    assert status == 502
    assert corpo == {"erro": "o provedor recusou", "codigo": codigo}


def test_configuracao_incompleta_vira_503_listando_o_que_falta():
    registro = []
    app = criar_app(Configuracao(url_base="https://g/v1", chave="", modelo=""), provedor_que_responde(registro))

    status, corpo = chamar(app, "POST", "/api/chat", PEDIDO)

    assert status == 503
    assert corpo["faltando"] == ["LLM_API_KEY", "LLM_MODEL"]
    assert "LLM_API_KEY" in corpo["erro"]
    assert registro == []


@pytest.mark.parametrize(
    "corpo, campo",
    [
        ({"sistema": "", "mensagens": "Oi"}, "mensagens"),
        ({"sistema": "", "mensagens": [{"papel": "usuario"}]}, "conteudo"),
        ({"sistema": "", "mensagens": [{"papel": "usuario", "conteudo": 3}]}, "conteudo"),
        ({"sistema": 1, "mensagens": [{"papel": "usuario", "conteudo": "Oi"}]}, "sistema"),
        ({"modelo": 7, "sistema": "", "mensagens": [{"papel": "usuario", "conteudo": "Oi"}]}, "modelo"),
        ({"sistema": ""}, "mensagens"),
        ([1, 2], "corpo"),
    ],
)
def test_campo_ausente_ou_com_tipo_errado_vira_400_citando_o_campo(corpo, campo):
    registro = []
    app = criar_app(CONFIG, provedor_que_responde(registro))

    status, resposta = chamar(app, "POST", "/api/chat", corpo)

    assert status == 400
    assert campo in resposta["erro"]
    assert registro == []


def test_corpo_que_nao_e_json_vira_400():
    registro = []
    app = criar_app(CONFIG, provedor_que_responde(registro))

    status, resposta = chamar(app, "POST", "/api/chat", bruto=b"{isto nao e json")

    assert status == 400
    assert "JSON" in resposta["erro"]
    assert registro == []


def test_modelos_devolve_a_lista_permitida_e_o_padrao():
    config = Configuracao(url_base="https://g/v1", chave="k", modelo="m-padrao", modelos_permitidos=("m-padrao", "m-2"))
    app = criar_app(config, provedor_que_responde([]))

    status, corpo = chamar(app, "GET", "/api/modelos")

    assert (status, corpo) == (200, {"modelos": ["m-padrao", "m-2"], "padrao": "m-padrao"})


def test_modelos_sem_a_variavel_tem_so_o_padrao():
    app = criar_app(CONFIG, provedor_que_responde([]))

    status, corpo = chamar(app, "GET", "/api/modelos")

    assert (status, corpo) == (200, {"modelos": ["m-padrao"], "padrao": "m-padrao"})


def test_modelo_fora_da_lista_vira_400_sem_chamar_o_provedor():
    registro = []
    app = criar_app(CONFIG, provedor_que_responde(registro))

    status, corpo = chamar(app, "POST", "/api/chat", {**PEDIDO, "modelo": "m-estranho"})

    assert status == 400
    assert "modelo" in corpo["erro"]
    assert registro == []


def test_modelo_da_lista_e_aceito():
    config = Configuracao(url_base="https://g/v1", chave="k", modelo="m-padrao", modelos_permitidos=("m-padrao", "m-2"))
    registro = []
    app = criar_app(config, provedor_que_responde(registro))

    status, corpo = chamar(app, "POST", "/api/chat", {**PEDIDO, "modelo": "m-2"})

    assert (status, corpo["modelo"]) == (200, "m-2")
    assert registro[0][0] == "m-2"


def test_prompts_devolve_as_skills_da_pasta_configurada(tmp_path):
    (tmp_path / "triagem-do-alerta").mkdir()
    (tmp_path / "triagem-do-alerta" / "SKILL.md").write_text("---\nname: t\n---\n# Triagem do alerta\n\ncorpo\n", encoding="utf-8")
    app = criar_app(CONFIG, provedor_que_responde([]), pasta_de_skills=tmp_path)

    status, corpo = chamar(app, "GET", "/api/prompts")

    assert status == 200
    assert corpo == {"prompts": [{"nome": "triagem-do-alerta", "titulo": "Triagem do alerta", "texto": "# Triagem do alerta\n\ncorpo"}]}


def test_prompts_por_padrao_le_as_skills_dos_agentes_do_repositorio():
    app = criar_app(CONFIG, provedor_que_responde([]))

    status, corpo = chamar(app, "GET", "/api/prompts")

    assert status == 200
    assert "triagem-do-alerta" in [p["nome"] for p in corpo["prompts"]]


def test_sistema_acima_do_limite_vira_400_sem_chamar_o_provedor():
    registro = []
    app = criar_app(CONFIG, provedor_que_responde(registro))

    status, corpo = chamar(app, "POST", "/api/chat", {**PEDIDO, "sistema": "x" * 20_001})

    assert status == 400
    assert "sistema" in corpo["erro"]
    assert registro == []


def test_sistema_no_limite_e_aceito_e_chega_ao_provedor():
    registro = []
    app = criar_app(CONFIG, provedor_que_responde(registro))

    status, _ = chamar(app, "POST", "/api/chat", {**PEDIDO, "sistema": "x" * 20_000})

    assert status == 200
    assert registro[0][1] == "x" * 20_000


def conversa(quantidade, tamanho=2):
    """`quantidade` mensagens alternando pessoa e modelo, terminando na pessoa, com `tamanho` caracteres cada."""
    papeis = ["usuario" if (quantidade - i) % 2 == 1 else "assistente" for i in range(quantidade)]
    return [{"papel": papel, "conteudo": "x" * tamanho} for papel in papeis]


@pytest.mark.parametrize(
    "corpo, trecho",
    [
        ({**PEDIDO, "mensagens": [{"papel": "usuario", "conteudo": "x" * 8_001}]}, "conteudo"),
        ({**PEDIDO, "mensagens": conversa(41)}, "mensagens"),
        ({**PEDIDO, "sistema": "", "mensagens": conversa(11, 7_900)}, "soma"),
        ({**PEDIDO, "sistema": "s" * 20_000, "mensagens": conversa(9, 7_000)}, "soma"),
        ({**PEDIDO, "mensagens": []}, "mensagens"),
        ({**PEDIDO, "mensagens": [{"papel": "usuario", "conteudo": "Oi"}, {"papel": "assistente", "conteudo": "Olá"}]}, "última mensagem"),
        ({**PEDIDO, "mensagens": [{"papel": "sistema", "conteudo": "Oi"}]}, "papel"),
    ],
)
def test_limites_de_tamanho_e_forma_da_conversa_viram_400_sem_chamar_o_provedor(corpo, trecho):
    registro = []
    app = criar_app(CONFIG, provedor_que_responde(registro))

    status, resposta = chamar(app, "POST", "/api/chat", corpo)

    assert status == 400
    assert trecho in resposta["erro"]
    assert registro == []


@pytest.mark.parametrize(
    "corpo",
    [
        {**PEDIDO, "mensagens": [{"papel": "usuario", "conteudo": "x" * 8_000}]},
        {**PEDIDO, "mensagens": conversa(40)},
        {**PEDIDO, "sistema": "", "mensagens": conversa(10, 8_000)},
    ],
)
def test_no_limite_a_conversa_e_aceita(corpo):
    registro = []
    app = criar_app(CONFIG, provedor_que_responde(registro))

    status, _ = chamar(app, "POST", "/api/chat", corpo)

    assert status == 200
    assert len(registro) == 1


def pasta_construida(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>SentryIoT</title>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path / "segredo.txt").write_text("fora da pasta", encoding="utf-8")
    return dist


def test_com_a_pasta_construida_serve_o_index_na_raiz_e_os_arquivos_com_o_tipo_certo(tmp_path):
    app = criar_app(CONFIG, provedor_que_responde([]), pasta_construida=pasta_construida(tmp_path))

    status, cabecalhos, texto = chamar_bruto(app, "GET", "/")
    assert (status, texto) == (200, "<!doctype html><title>SentryIoT</title>")
    assert cabecalhos["content-type"].startswith("text/html")

    status, cabecalhos, texto = chamar_bruto(app, "GET", "/assets/app.js")
    assert (status, texto) == (200, "console.log(1)")
    assert "javascript" in cabecalhos["content-type"]


def test_caminho_desconhecido_fora_de_api_devolve_o_index(tmp_path):
    app = criar_app(CONFIG, provedor_que_responde([]), pasta_construida=pasta_construida(tmp_path))

    status, _, texto = chamar_bruto(app, "GET", "/qualquer/coisa")

    assert (status, texto) == (200, "<!doctype html><title>SentryIoT</title>")


@pytest.mark.parametrize("com_pasta", [True, False])
@pytest.mark.parametrize("caminho", ["/api/nada", "/api", "/api/"])
def test_rota_de_api_inexistente_devolve_404_em_json(tmp_path, com_pasta, caminho):
    pasta = pasta_construida(tmp_path) if com_pasta else tmp_path / "nao-existe"
    app = criar_app(CONFIG, provedor_que_responde([]), pasta_construida=pasta)

    status, corpo = chamar(app, "GET", caminho)

    assert status == 404
    assert "erro" in corpo


def test_sem_a_pasta_construida_a_raiz_da_404_e_a_api_continua(tmp_path):
    app = criar_app(CONFIG, provedor_que_responde([]), pasta_construida=tmp_path / "nao-existe")

    assert chamar(app, "GET", "/")[0] == 404
    assert chamar(app, "GET", "/api/modelos") == (200, {"modelos": ["m-padrao"], "padrao": "m-padrao"})


# O servidor ASGI entrega o caminho já decodificado; os casos cobrem o `..` solto e no meio.
@pytest.mark.parametrize("caminho", ["/../segredo.txt", "/assets/../../segredo.txt", "/../../segredo.txt"])
def test_caminho_que_sai_da_pasta_construida_nao_e_servido(tmp_path, caminho):
    app = criar_app(CONFIG, provedor_que_responde([]), pasta_construida=pasta_construida(tmp_path))

    status, _, texto = chamar_bruto(app, "GET", caminho)

    # Caminho que não é arquivo da pasta recebe o index, nunca o arquivo de fora.
    assert (status, texto) == (200, "<!doctype html><title>SentryIoT</title>")


def test_excecao_inesperada_do_provedor_vira_500_sem_vazar_detalhe():
    def chamar_provedor(modelo, sistema, mensagens):
        raise RuntimeError("segredo interno")

    app = criar_app(CONFIG, chamar_provedor)

    status, corpo = chamar(app, "POST", "/api/chat", PEDIDO)

    assert status == 500
    assert "segredo" not in json.dumps(corpo)
