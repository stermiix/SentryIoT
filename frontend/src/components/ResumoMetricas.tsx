import type { IncidenteView, ResumoGeral } from "../types";

interface Props {
  resumo: ResumoGeral;
  incidentes: IncidenteView[];
}

export default function ResumoMetricas({ resumo, incidentes }: Props) {
  const ativos = incidentes.filter((item) => item.incidente?.estado === "aberto").length;
  const cartoes = [
    { rotulo: "Janelas analisadas", valor: resumo.janelasClassificadas.toLocaleString("pt-BR"), detalhe: "em todos os lotes do replay", cor: "azul", icone: "▦" },
    { rotulo: "Incidentes", valor: String(resumo.totalIncidentes), detalhe: `${ativos} em acompanhamento`, cor: "ambar", icone: "⌁" },
    { rotulo: "Chamadas à IA", valor: String(resumo.chamadasLLM), detalhe: `${resumo.tokens.toLocaleString("pt-BR")} tokens no replay`, cor: "violeta", icone: "✳" },
  ];

  return (
    <section className="metricas" aria-label="Resumo do replay">
      {cartoes.map((cartao) => (
        <article className="metrica-card" key={cartao.rotulo}>
          <div className={`metrica-icone ${cartao.cor}`} aria-hidden="true">{cartao.icone}</div>
          <div className="metrica-conteudo">
            <span className="metrica-rotulo">{cartao.rotulo}</span>
            <strong className="metrica-valor">{cartao.valor}</strong>
            <span className="metrica-detalhe">{cartao.detalhe}</span>
          </div>
          <span className="metrica-indicador" aria-hidden="true">↗</span>
        </article>
      ))}
    </section>
  );
}
