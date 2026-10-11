import { inteiro } from "../formato";
import type { IncidenteView, ResumoGeral } from "../types";

interface Props {
  resumo: ResumoGeral;
  incidentes: IncidenteView[];
}

export default function ResumoMetricas({ resumo, incidentes }: Props) {
  // Em acompanhamento: aberto no classificador e sem a marca de já resolvido.
  const ativos = incidentes.filter((item) => item.incidente.estado === "aberto" && !item.marcacao).length;
  const cartoes = [
    { rotulo: "Janelas analisadas", valor: inteiro(resumo.janelasClassificadas), detalhe: "em todos os lotes do replay", cor: "azul", icone: "▦" },
    { rotulo: "Incidentes", valor: String(resumo.totalIncidentes), detalhe: `${ativos} em acompanhamento`, cor: "ambar", icone: "⌁" },
    { rotulo: "Chamadas à IA", valor: String(resumo.chamadasLLM), detalhe: `${inteiro(resumo.tokens)} tokens no replay`, cor: "violeta", icone: "✳" },
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
