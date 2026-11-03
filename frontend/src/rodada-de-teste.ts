// Só para os testes: um índice como o que `vitrine.py` grava, com execuções de mentira. Só a forma importa.

import type { ExecucaoDaRodada, GrupoDaRodada, IndiceDaRodada } from "./rodada";

export function execucaoDeTeste(grupo: string, pcap: string, incidente: string, repeticao: number, outras: Partial<ExecucaoDaRodada> = {}): ExecucaoDaRodada {
  const rodada = `${pcap.replace(/\.pcap$/, "")}-${incidente}-local-r${repeticao}`;
  return {
    id: `${grupo}/${rodada}`, rodada, pcap, incidente, repeticao, categoria_do_pcap: "DDoS", categoria: "DDoS", verdadeiro: true,
    confianca: 0.97, deteccao_s: 0.5, desfecho: "resolvido", erro: null, triagem_rotulo: "coerente", triagem_correta: true,
    n_propostas: 1, n_aceitaveis: 1, primeira_aceitavel: true, acao_primeira: "bloquear_ip", n_aprovadas: 1, n_rejeitadas: 0,
    n_baixo_risco: 0, n_novas: 0, atacante_apontado: true, atacante_certo: true, origem_da_regra_certa: false, agentes_s: 61.2,
    chamadas: 9, tokens_entrada: 52000, tokens_saida: 900, llm_s: 50.1, modelos: ["qwen3.8-27c"], conversas: 3, avisos: [],
    log: `${grupo}/${rodada}.jsonl.gz`, bytes: 1000, ...outras,
  };
}

const RESUMO = {
  execucoes: 0, com_erro: 0, pcaps: 0, incidentes: 0, repeticoes: 1, verdadeiras: 0, falsas: 0,
  triagem_correta: { acertos: 0, de: 0 }, acao_aceitavel: { acertos: 0, de: 0 }, atacante_certo: { acertos: 0, de: 0 },
  regra_fixa_certa: { acertos: 0, de: 0 }, abaixo_da_confianca_minima: 0, desfechos: {}, chamadas: 0, tokens_entrada: 0,
  tokens_saida: 0, mediana_tokens: null, mediana_agentes_s: null, mediana_deteccao_s: null, por_agente: [],
};

export function grupoDeTeste(id: string, titulo: string, execucoes: ExecucaoDaRodada[]): GrupoDaRodada {
  const resumo = {
    ...RESUMO,
    execucoes: execucoes.length,
    pcaps: new Set(execucoes.map((item) => item.pcap)).size,
    incidentes: new Set(execucoes.map((item) => `${item.pcap} ${item.incidente}`)).size,
    chamadas: execucoes.reduce((soma, item) => soma + item.chamadas, 0),
    por_agente: [
      { agente: "triagem" as const, execucoes: execucoes.length, chamadas: 4, tokens_entrada: 30000, tokens_saida: 400, llm_s: 20, mediana_tokens: 30400, mediana_llm_s: 20 },
      { agente: "decisao" as const, execucoes: execucoes.length, chamadas: 3, tokens_entrada: 20000, tokens_saida: 300, llm_s: 15, mediana_tokens: 20300, mediana_llm_s: 15 },
    ],
  };
  return { id, titulo, descricao: "", conjunto_gerado_em: null, resumo, execucoes };
}

export function indiceDeTeste(): IndiceDaRodada {
  return {
    versao: 1,
    configuracao: "local",
    modelos: ["qwen3.8-27c"],
    confianca_minima_para_propor: 0.6,
    inicial: "oficial/DDoS-UDP_Flood-inc-0002-local-r1",
    grupos: [
      grupoDeTeste("oficial", "Rodada oficial (CICIoT2023)", [
        execucaoDeTeste("oficial", "DDoS-UDP_Flood.pcap", "inc-0001", 1),
        execucaoDeTeste("oficial", "DDoS-UDP_Flood.pcap", "inc-0001", 2, { desfecho: "sem_proposta" }),
        execucaoDeTeste("oficial", "DDoS-UDP_Flood.pcap", "inc-0002", 1),
        execucaoDeTeste("oficial", "DDoS-UDP_Flood.pcap", "inc-0002", 2),
        execucaoDeTeste("oficial", "Recon-PortScan.pcap", "inc-0001", 1, { categoria_do_pcap: "Recon", categoria: "Recon" }),
        execucaoDeTeste("oficial", "BenignTraffic2.pcap", "inc-0001", 2, { categoria_do_pcap: "Benign", verdadeiro: false }),
      ]),
      grupoDeTeste("kali", "Kali Linux, rede isolada", [execucaoDeTeste("kali", "kali-nmap.pcap", "inc-0001", 1, { categoria_do_pcap: "Recon" })]),
    ],
  };
}
