---
name: analise-por-categoria
description: Interpreta o padrão do ataque dentro da categoria já triada (DDoS, DoS, Mirai, Recon, Spoofing, Web ou BruteForce), usando o resumo do incidente para entender o que está acontecendo antes de escolher uma mitigação. Usar depois da triagem-do-alerta e antes da recomendacao-de-mitigacao, sempre que o rótulo da triagem for "coerente".
---

# Análise por categoria de ataque

Skill do agente de **decisão** (ver `codigo/mcp/README.md`), primeira metade do trabalho dele:
entender o ataque antes de recomendar o que fazer. A segunda metade é a skill
`recomendacao-de-mitigacao`.

## Onde roda e o que chega aqui

O agente de decisão é o único que pode rodar num modelo de fronteira pela nuvem (arquitetura
híbrida, `ROADMAP.md`, decisão de 2026-10-10). Nada identificável da rede chega a ele, e isso é
garantido pelo servidor: a linha de decisão não tem `obter_incidente` nem `obter_janelas`, que
trazem endereços, e toda resposta a ela passa por um filtro que troca endereço por `[endereço]`.
Os endereços do incidente chegam como rótulos neutros (`origem-1`, `destino-1`), e a análise
trabalha com esses rótulos, as contagens, a confiança e as features. Não há o que descobrir por
trás de um rótulo, e a análise não deve tentar. Na configuração toda local, os dados chegam do
mesmo jeito, para o fluxo ser o mesmo nas três configurações comparadas no artigo.

## Quando usar

- Depois que a `triagem-do-alerta` devolve o rótulo **coerente** para o incidente.
- Em incidente **duvidoso**, a análise serve só para apoiar a decisão de pedir uma reavaliação à
  triagem ou de escalar para a pessoa, e não para justificar uma ação de risco alto.

## O que a tool MCP devolve

- `obter_resumo(id)`: o resumo montado pelo servidor, que é tudo o que esta skill usa.
  - `categoria` (8 categorias, com DDoS e DoS separados) e `categoria_do_modelo` (as 7 do modelo,
    com `DDoS+DoS` junto); `confianca`; `duracao_s`; `janelas`; `origens_distintas`;
    `distribuido`.
  - `origens` e `destinos`: cada um com `rotulo`, `quadros` e `protegido`, que diz se o endereço
    é protegido pela política (o gateway, a máquina de captura, os serviços críticos).
  - `features_principais`: cada uma com `nome` (uma das 39 colunas do extrator), `valor` e
    `referencia_benigno`, o valor típico no tráfego benigno.
  - `portas`: até 5 portas de destino do TCP e do UDP que mais receberam quadros, cada uma com o
    `destino` (o rótulo), a `porta`, o `protocolo` e os `quadros`. Vem vazia sem TCP nem UDP.
  - `estado`, `ja_resolvido` e `ultimo_efeito`: o que já foi tentado e se a pessoa já resolveu.

Quando o resumo não basta para confirmar o padrão, o caminho é pedir uma reavaliação à triagem,
que tem as janelas. O agente de decisão não lê janelas nem a política de risco: quem decide o
risco é o servidor, em `propor_acao`.

## Passo a passo (o que olhar em cada categoria)

As 39 features descrevem uma janela de 100 quadros (decisão de 2026-10-10): não há porta nem
endereço entre elas. O que existe de camada de aplicação são os indicadores de protocolo
(`HTTP`, `HTTPS`, `DNS`, `Telnet`, `SSH`, `TCP`, `UDP`, `ICMP`, `ARP` e os demais), que dizem a
fração da janela em cada protocolo. As portas atacadas vêm à parte, em `portas`, contadas pelo
servidor nos cabeçalhos de transporte: é ali que a análise responde "em quais portas". Uma
porta que concentra os quadros (23 ou 2323 do Telnet, 22 do SSH, 80 do HTTP) diz qual serviço o
ataque mira; muitas portas com poucos quadros cada são o retrato de uma varredura. Fora dessas
cinco, a resposta não está nos dados: dizer isso em vez de inventar.

- **DDoS e DoS**: `Rate` muito acima da referência do tráfego benigno, `syn_count` ou `ack_count`
  altos, e `origens_distintas` (DDoS tem muitas, DoS poucas; a separação já vem pronta em
  `categoria` e não precisa ser recalculada aqui). Confirmar se o padrão é volumétrico (`Rate`)
  ou de exaustão de recursos (contagem de flags). Pacote pequeno (`AVG`, `Tot size`) com `Rate`
  alto é flood de SYN, RST ou ICMP; `UDP` alto com `Rate` alto é flood UDP.
- **Mirai**: `Rate` alto com `UDP` ou `TCP` dominando a janela, pacotes de tamanho quase
  constante (`Std` e `Variance` baixos), muitas vezes com mais de um destino.
- **Recon**: `syn_count` com `rst_count` na mesma proporção (porta fechada responde RST),
  pacotes pequenos, `Time_To_Live` estável, poucas origens; no ping sweep, `ICMP` domina.
- **Spoofing**: `ARP` ou `DNS` acima da referência do tráfego benigno numa rede em que esse
  tráfego é raro. Se um destino vem com `protegido` verdadeiro (o gateway, por exemplo), dizer:
  qualquer ação sobre ele dependerá da pessoa.
- **Web**: `HTTP` ou `HTTPS` dominando, `Rate` mais baixo que em DDoS e DoS, com risco de
  confundir com tráfego legítimo de alto volume; comparar sempre com `referencia_benigno`. É a
  categoria em que o classificador mais erra (recall abaixo de 40%,
  `experimentos/resultados/regeracao.md`).
- **BruteForce**: muitas janelas seguidas com a mesma origem e o mesmo destino, `Rate` moderado,
  `SSH` ou `Telnet` presentes, característico de tentativa repetida (ver o cenário `inc-0002` em
  `codigo/mcp/README.md`). O recall também é baixo; a precisão é alta, então o rótulo, quando
  vem, costuma estar certo.

## Formato da resposta

Entrada para a skill `recomendacao-de-mitigacao`, não para a pessoa diretamente. Endereço só por
rótulo:

```
Incidente: <id>  |  Categoria: <categoria>
Padrão observado: <1–2 frases, o que no tráfego caracteriza esse ataque específico>
Features que sustentam a leitura: <nome: valor (referência benigno: x), até 3>
Alvos envolvidos: <rótulos que importam, como origem-1 ou destino-1, e se algum é protegido>
Portas atacadas: <as que importam, como 23/tcp em destino-1, ou "nenhuma no resumo">
Urgência percebida: baixa | média | alta
```

"Urgência percebida" não é o risco da ação (esse é calculado pelo servidor em `propor_acao`), é
só um sinal para a próxima skill priorizar entre mitigações equivalentes.
