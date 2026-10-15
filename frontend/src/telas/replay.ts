import { useCallback, useEffect, useMemo, useState } from "react";
import { estadoNoPasso, linhasDoLog, marcasDoReplay, type EstadoDaTela } from "../adaptador";
import type { ReplayMark } from "../design-system/components/Replay";
import type { LogEvent } from "../design-system/components/modelos";
import { agregar, type Agregado } from "../log";
import type { Rota } from "../rotas";
import type { Evento } from "../types";

// O que toda tela recebe: o log lido, a posição do replay e como navegar.

export interface Replay {
  eventos: Evento[];
  linhas: LogEvent[];
  /** Avisos da leitura e da reconstrução do log inteiro. */
  avisos: string[];
  passo: number;
  irPara: (passo: number) => void;
  tocando: boolean;
  alternar: () => void;
  /** O estado das telas até o passo. */
  estado: EstadoDaTela;
  /** A montagem do log inteiro: o que vem depois do cursor, no histórico. */
  final: Agregado;
  marcas: ReplayMark[];
}

export interface PropsDaTela {
  replay: Replay;
  navegar: (rota: Rota) => void;
}

// Um evento a cada 700 ms quando o replay está tocando.
const INTERVALO_MS = 700;

/** Monta o `Replay` a partir dos eventos: tudo que depende só do log é calculado uma vez. */
export function montarReplay(eventos: Evento[], avisos: string[], passo: number, controles: Pick<Replay, "irPara" | "tocando" | "alternar">): Replay {
  const final = agregar(eventos);
  const linhas = linhasDoLog(eventos, final.ignorados);
  return {
    eventos,
    linhas,
    avisos,
    passo,
    ...controles,
    estado: estadoNoPasso(eventos, linhas, passo),
    final,
    marcas: marcasDoReplay(eventos, final.ignorados),
  };
}

/** O replay com estado: começa no fim do log, anda com `irPara` e toca evento a evento. */
export function useReplay(eventos: Evento[], avisos: string[]): Replay {
  const total = eventos.length;
  const [passo, setPasso] = useState(total);
  const [tocando, setTocando] = useState(false);
  // Log novo: o replay vai para o fim dele já no mesmo desenho, sem passar pelo passo 0.
  const [doLog, setDoLog] = useState(eventos);
  if (doLog !== eventos) {
    setDoLog(eventos);
    setPasso(total);
    setTocando(false);
  }

  useEffect(() => {
    if (!tocando) {
      return;
    }
    const relogio = window.setInterval(() => setPasso((atual) => Math.min(total, atual + 1)), INTERVALO_MS);
    return () => window.clearInterval(relogio);
  }, [tocando, total]);
  // No último evento, o replay para sozinho.
  useEffect(() => {
    if (tocando && passo >= total) {
      setTocando(false);
    }
  }, [tocando, passo, total]);

  const irPara = useCallback((novo: number) => setPasso(Math.max(1, Math.min(total, novo))), [total]);
  // Tocar a partir do fim recomeça do primeiro evento.
  const alternar = useCallback(() => {
    if (!tocando && passo >= total) {
      setPasso(1);
    }
    setTocando(!tocando);
  }, [tocando, passo, total]);

  const final = useMemo(() => agregar(eventos), [eventos]);
  const linhas = useMemo(() => linhasDoLog(eventos, final.ignorados), [eventos, final]);
  const marcas = useMemo(() => marcasDoReplay(eventos, final.ignorados), [eventos, final]);
  const estado = useMemo(() => estadoNoPasso(eventos, linhas, passo), [eventos, linhas, passo]);
  return { eventos, linhas, avisos, passo, irPara, tocando, alternar, estado, final, marcas };
}
