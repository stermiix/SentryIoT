// Os valores fixos do contrato do log (`codigo/mcp/contrato.json`, gerado de `codigo/mcp/tipos.py`).
// Os tipos de `types.ts` saem destas listas, e `contrato.test.ts` compara cada uma com o
// `contrato.json`: quando o contrato muda e a interface não acompanha, o teste falha.

export const CATEGORIAS = ["DDoS", "DoS", "Mirai", "Recon", "Spoofing", "Web", "BruteForce", "Benign"] as const;
// O modelo não separa DDoS de DoS: a separação sai da quantidade de origens e só existe em `categoria`.
export const CATEGORIAS_DO_MODELO = ["DDoS+DoS", "Mirai", "Recon", "Spoofing", "Web", "BruteForce", "Benign"] as const;
export const AGENTES = ["triagem", "decisao", "execucao"] as const;
export const CANAIS = ["terminal", "interface"] as const;
export const RISCOS = ["baixo", "alto"] as const;
export const ESTADOS_DO_INCIDENTE = ["aberto", "encerrado"] as const;
export const ESTADOS_DA_PROPOSTA = ["aguardando_aprovacao", "liberada", "rejeitada", "executada", "desfeita"] as const;
export const ESTADOS_DA_EXECUCAO = ["aplicada", "desfeita"] as const;
export const RESULTADOS_DO_EFEITO = ["cessou", "diminuiu", "persiste"] as const;
export const ORIGENS_DE_ACAO = ["base", "promovida"] as const;
export const PROTOCOLOS_DE_TRANSPORTE = ["tcp", "udp"] as const;
// Onde o modelo de uma chamada rodou (`llm_chamada.onde`).
export const LUGARES_DO_MODELO = ["local", "nuvem"] as const;
// Por que o laço de um agente parou (`agente_concluido.motivo`), na ordem de `tipos.py`.
export const MOTIVOS_DE_PARADA = [
  "resposta_final",
  "limite_de_voltas",
  "chamada_repetida",
  "limite_de_tools",
  "limite_do_historico",
  "resposta_incompleta",
  "resposta_vazia",
  "recusa_do_provedor",
  "limite_de_saida",
] as const;
// O rótulo da triagem (`agente_concluido.veredito`): ruído vem sem acento, como no contrato.
export const VEREDITOS_DA_TRIAGEM = ["coerente", "duvidoso", "ruido"] as const;

// Código de cada motivo de risco alto e a frase que a pessoa lê antes de aprovar. A tela mostra
// esta frase, que é do sistema, e não a que veio no log.
export const MOTIVOS_DE_RISCO_ALTO = {
  acao_sempre_de_risco_alto: "A ação é sempre de risco alto, qualquer que seja o alvo ou o prazo.",
  acao_nova: "A ação é nova, fora do catálogo.",
  prazo_acima_do_limite: "A medida não tem prazo, ou o prazo pedido passa do máximo aceito para risco baixo.",
  alvo_fora_do_incidente: "O alvo não está entre as origens nem entre os destinos do incidente.",
  alvo_e_destino_do_incidente:
    "O alvo é destino do incidente, isto é, o dispositivo atacado, e esta ação só é de risco baixo sobre uma origem.",
  alvo_na_rede_local: "O alvo é um endereço da rede local, e bloqueá-lo equivale a isolar um dispositivo interno.",
  alvo_protegido: "O alvo é um endereço protegido pela política.",
  // Desde o contrato 0.7.0.
  alvo_rejeitado: "A pessoa já rejeitou uma ação neste alvo neste incidente.",
  orcamento_de_risco_baixo_esgotado: "O incidente já tem o máximo de medidas de risco baixo ativas.",
  orcamento_global_de_risco_baixo_esgotado:
    "O sistema já tem o máximo de medidas de risco baixo ativas, somando todos os incidentes.",
} as const;
export const CODIGOS_DE_RISCO_ALTO = Object.keys(MOTIVOS_DE_RISCO_ALTO) as (keyof typeof MOTIVOS_DE_RISCO_ALTO)[];

export const MOTIVOS_DE_RECUSA = [
  "identificador_desconhecido",
  "argumentos_invalidos",
  "alvo_malformado",
  "alvo_nao_permitido",
  "incidente_encerrado",
  "incidente_ja_resolvido",
  "limite_de_propostas_pendentes",
  "limite_de_propostas_liberadas",
  // Desde o contrato 0.7.0.
  "proposta_repetida",
  "incidente_duvidoso",
  "acao_nova_incompleta",
  "proposta_nao_liberada",
  "proposta_ja_executada",
  "acao_nao_aplicada",
  "tool_fora_da_linha",
] as const;

// As 39 colunas do extrator, que são os nomes possíveis de uma feature em destaque.
export const COLUNAS = [
  "Header_Length", "Protocol Type", "Time_To_Live", "Rate", "fin_flag_number", "syn_flag_number",
  "rst_flag_number", "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number", "ack_count",
  "syn_count", "fin_count", "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP",
  "DHCP", "ARP", "ICMP", "IGMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number",
  "Variance",
] as const;

export const TIPOS_DE_EVENTO = [
  "janelas_classificadas",
  "incidente_aberto",
  "incidente_atualizado",
  "incidente_encerrado",
  "incidente_marcado_resolvido",
  "llm_chamada",
  "tool_chamada",
  "agente_concluido",
  "atacante_apontado",
  "analise_emitida",
  "recomendacao_emitida",
  "sumario_emitido",
  "acao_proposta",
  "acao_aprovada",
  "acao_rejeitada",
  "acao_executada",
  "acao_desfeita",
  "efeito_verificado",
  "catalogo_ampliado",
  "recusa",
] as const;

// Limites de `tipos.py`.
export const TEXTO_CURTO = 200;
export const TEXTO_LONGO = 2_000;
export const MAXIMO_DE_PASSOS = 20;
export const MAXIMO_DE_PROPOSTAS_POR_RECOMENDACAO = 20;
// Candidatos a atacante por incidente, e destinos e portas citados de cada um (contrato 0.6.0).
export const MAXIMO_DE_CANDIDATOS = 5;
export const DESTINOS_DO_CANDIDATO = 3;
export const PORTAS_DO_CANDIDATO = 3;

// O catálogo de base e as ações que são sempre de risco alto não estão no contrato: vêm de
// `BASE` e `_SEMPRE_DE_RISCO_ALTO`, em `codigo/mcp/acoes.py`, e `contrato.test.ts` também as confere
// lá. A reconstrução precisa delas para as mesmas regras do `reconstruir`.
export const ACOES_DE_BASE = [
  "limitar_taxa",
  "bloquear_ip",
  "isolar_dispositivo",
  "revogar_credencial",
  "fechar_porta",
] as const;
export const SEMPRE_DE_RISCO_ALTO = ["isolar_dispositivo", "revogar_credencial", "fechar_porta"] as const;
