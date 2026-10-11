import { hora, instanteCompleto } from "../formato";

/** A hora de um evento no fuso local. O `title` traz a data, os milissegundos e o fuso. */
export default function Instante({ valor }: { valor: string }) {
  return (
    <time className="instante" dateTime={valor} title={instanteCompleto(valor)}>
      {hora(valor)}
    </time>
  );
}
