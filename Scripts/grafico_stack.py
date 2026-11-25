# grafico_stack_por_iteracao.py
# Barras agrupadas (128/192/256 × ML-DSA/ECDSA/RSA), eixo Y linear (bytes).
# TXT: "Rótulo: valor_em_bytes" (aceita vírgula decimal; "NA" pula; "/ ..." é ignorado).
# RSA-15360: se ausente, estima por ajuste linear em função do tamanho da chave (bits),
# e desenha uma ghostbar (faixa ±15% em torno do valor estimado).

import sys, math
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from matplotlib.ticker import MultipleLocator

# ----- Config -----
COLORS = {"ML-DSA": "#00ff00", "ECDSA": "#0000ff", "RSA": "#ff0000"}
BAR_WIDTH = 0.25
ESTIMATE_PRESENTATION = "ghostbar"   # "ghostbar" ou "callout"
SHOW_CENTRAL_MARK = True             # traço pontilhado dentro da ghostbar
GHOST_PCT_BAND = 0.15                # ±15% ao redor da estimativa (stack muda pouco)
TOP_LABELS = False                    # rótulo com o valor exato no topo das barras

# legenda da anotação
CALLOUT_BOX_KW = dict(
    boxstyle="round,pad=0.3", facecolor="#ede1ff",
    alpha=0.6, edgecolor="#6b4ca5", linewidth=1.0
)

def _num(s: str):
    s = s.strip()
    if s.upper() in {"NA", "N/A", ""}: return None
    s = s.replace(",", ".")
    try:
        return float(s)
    except:
        return None

def normalize_label(lbl: str) -> str:
    x = lbl.strip().lower()
    x = x.replace(" ", "").replace("_", "").replace("—", "-").replace("–", "-")
    x = x.replace("crystal-kybers", "ml-dsa").replace("crystalkybers", "ml-dsa").replace("kyber", "ml-dsa")
    return x

def parse_line(line: str):
    if ":" not in line:
        return None
    k, rest = line.split(":", 1)
    lbl = normalize_label(k)
    first = rest.split("/")[0].strip()
    # Tenta ler até 3 números: valor, low, high
    parts = [_num(p) for p in first.split(",")]
    v_bytes = parts[0] if len(parts) >= 1 else None
    low_ci  = parts[1] if len(parts) >= 2 else None
    high_ci = parts[2] if len(parts) >= 3 else None
    if v_bytes is not None and v_bytes <= 0:
        v_bytes = None
    return (lbl, v_bytes, low_ci, high_ci)

def compute_rsa15360_stack_band(s3072, s7680, pct=GHOST_PCT_BAND):
    """
    Estima stack para 15360 por ajuste linear em função de nbits:
      s(n) ≈ a + b*n   usando (n1=3072, s1) e (n2=7680, s2)
    Retorna (low, cent, high, slope_b).
    """
    if s3072 is None or s7680 is None or s3072 <= 0 or s7680 <= 0:
        return None
    n1, n2, n3 = 3072, 7680, 15360
    b = (s7680 - s3072) / (n2 - n1)
    a = s3072 - b * n1
    s15360 = a + b * n3
    # faixa ±pct (stack tende a variar pouco; incerteza conservadora)
    low  = max(0.0, s15360 * (1.0 - pct))
    high = s15360 * (1.0 + pct)
    return (low, s15360, high, b)

def fmt_bytes_int(x: float) -> str:
    # 13.616, 27.760 etc. (ponto como separador de milhar)
    s = f"{int(round(x)):,}"
    return s.replace(",", ".")

def main():
    if len(sys.argv) < 2:
        print("Uso: python grafico_stack_por_iteracao.py <arquivo_txt>")
        sys.exit(1)

    txt_path = Path(sys.argv[1])
    lines = txt_path.read_text(encoding="utf-8").splitlines()

    mapping = {
        # ML-DSA
        "ml-dsa-44": ("ML-DSA","N1"), "mldsa-44": ("ML-DSA","N1"), "kyber-44": ("ML-DSA","N1"),
        "ml-dsa-65": ("ML-DSA","N3"), "mldsa-65": ("ML-DSA","N3"), "kyber-65": ("ML-DSA","N3"),
        "ml-dsa-87":("ML-DSA","N5"), "mldsa-87":("ML-DSA","N5"), "kyber-87":("ML-DSA","N5"),
        # ECDSA
        "p-256": ("ECDSA","N1"), "p256": ("ECDSA","N1"), "ecdsa-p256": ("ECDSA","N1"),
        "p-384": ("ECDSA","N3"), "p384": ("ECDSA","N3"), "ecdsa-p384": ("ECDSA","N3"),
        "p-521": ("ECDSA","N5"), "p521": ("ECDSA","N5"), "ecdsa-p521": ("ECDSA","N5"),
        # RSA
        "rsa-3072": ("RSA","N1"), "rsa3072": ("RSA","N1"),
        "rsa-7680": ("RSA","N3"), "rsa7680": ("RSA","N3"),
        "rsa-15360":("RSA","N5"), "rsa15360":("RSA","N5"),
    }

    groups, algos = ["N1","N3","N5"], ["ML-DSA","ECDSA","RSA"]
    data = {g: {a: {"v": None, "ci": (None, None)} for a in algos} for g in groups}

    for ln in lines:
        parsed = parse_line(ln)
        if parsed:
            k, v_bytes, low_ci, high_ci = parsed
            if k in mapping:
                a, sec = mapping[k]
                data[sec][a] = {"v": v_bytes, "ci": (low_ci, high_ci)}

    # Estimativa RSA-15360 somente se não houver valor medido
    rsa15360_measured = data["N5"]["RSA"]["v"]
    rsa3072 = data["N1"]["RSA"]["v"]
    rsa7680 = data["N3"]["RSA"]["v"]
    band = None
    #if rsa15360_measured is None:
    #    band = compute_rsa15360_stack_band(rsa3072, rsa7680)
    #    if band:
    #        low, cent, high, slope = band
    #        print(f"[Predição RSA-15360] slope={slope:.4f} B/bit; low={low:.3f} B; central={cent:.3f} B; high={high:.3f} B")
    #    else:
    #        print("[Predição RSA-15360] Não foi possível estimar (faltam 3072/7680).")

    # ----- Plot -----
    x = np.arange(len(groups))
    fig, ax = plt.subplots(figsize=(9.6, 5.4))

    # barras principais
    for i, algo in enumerate(algos):
        offset = (i - 1) * BAR_WIDTH
        color = COLORS[algo]
        for j, g in enumerate(groups):
            v = data[g][algo]["v"]
            if v is None:
                continue
            xc = x[j] + offset
            rect = ax.bar(
                xc, v, BAR_WIDTH, color=color,
                edgecolor="#444", linewidth=0.5,
                label=algo if j == 0 else None, zorder=3
            )
            low_ci, high_ci = data[g][algo]["ci"]
            if low_ci is not None and high_ci is not None:
                err_low  = v - low_ci   # distância para baixo
                err_high = high_ci - v  # distância para cima
                ax.errorbar(
                    xc, v,
                    yerr=[[err_low], [err_high]],
                    fmt="none",           # sem marcador central
                    ecolor="dimgrey",
                    elinewidth=1.6,
                    capsize=10,
                    zorder=6
                )
            if TOP_LABELS:
                ax.text(xc, v, fmt_bytes_int(v), ha="center", va="bottom", fontsize=8)

    # eixo X/Y
    ax.set_xticks(x, [f"{g}" for g in groups])
    ax.set_xlabel("Nível de segurança")
    ax.set_ylabel("Uso de stack (bytes)")

    # limites Y (considerando ghostbar se existir)
    y_vals = []
    for g in groups:
        for a in algos:
            v = data[g][a]["v"]
            if v is not None and v > 0:
                y_vals.append(v)
    if band:
        low, cent, high, _ = band
        y_vals += [low, cent, high]

    if y_vals:
        ymax = max(y_vals)
        y_top = int(math.ceil((ymax * 1.15) / 1000) * 1000)  # arredonda para 1000
        ax.set_ylim(0, y_top)
        ax.yaxis.set_major_locator(MultipleLocator(base=2000))  # ticks a cada 2 kB (ajuste se quiser))

    ax.grid(True, which="major", axis="y", linewidth=0.6, zorder=0)

    # RSA-15360 estimado (ghostbar ancorada na coluna 256-bits)
    if band:
        j = groups.index("N5"); i = algos.index("RSA")
        xc = x[j] + (i - 1) * BAR_WIDTH
        left = xc - BAR_WIDTH/2
        low, cent, high, _ = band

        if ESTIMATE_PRESENTATION.lower() == "ghostbar":
            ax.add_patch(Rectangle(
                (left, low), BAR_WIDTH, max(high - low, 0),
                facecolor="none", edgecolor=COLORS["RSA"],
                hatch="//", linewidth=1.1, zorder=2, label="RSA-15360 (estimativa)"
            ))
            ax.plot([left, left+BAR_WIDTH], [low, low], lw=1.0, color=COLORS["RSA"], zorder=5)
            if SHOW_CENTRAL_MARK:
                ax.plot([left, left+BAR_WIDTH], [cent, cent], ls="--", lw=1.2, color=COLORS["RSA"], zorder=5)
            ax.text(xc, high*1.02, "estimado*", ha="center", va="bottom", fontsize=9)
            fig.text(0.01, 0.01, "*Extrapolado de RSA-3072/7680 - não medido.", fontsize=9)
        else:
            text = (f"RSA-15360 (estimativa)\n"
                    f"faixa: {fmt_bytes_int(low)}–{fmt_bytes_int(high)}\n"
                    f"central: {fmt_bytes_int(cent)}")
            ax.annotate(
                text, xy=(xc, cent), xycoords="data",
                xytext=(0.965, 0.86), textcoords="axes fraction",
                ha="right", va="top", bbox=CALLOUT_BOX_KW,
                arrowprops=dict(arrowstyle="->", color="#6b4ca5", lw=1.0)
            )
            if SHOW_CENTRAL_MARK:
                ax.hlines(cent, left, left+BAR_WIDTH, linestyles="--", lw=1.2, color=COLORS["RSA"], zorder=5)
            fig.text(0.01, 0.01, "Estimativa linear baseada em RSA-3072/7680 (stack); não medido.", fontsize=9)

    # legenda
    ax.legend(title="Algoritmo", ncols=3, frameon=False,
              loc="upper right", bbox_to_anchor=(0.5, 1.0), borderaxespad=0.2)

    plt.tight_layout(pad=0.2)
    out_png = txt_path.with_suffix(".stack.png")
    out_svg = txt_path.with_suffix(".stack.svg")
    plt.savefig(out_png, dpi=220, bbox_inches="tight")
    plt.savefig(out_svg, bbox_inches="tight")
    print(f"Gráficos salvos em: {out_png} e {out_svg}")

if __name__ == "__main__":
    main()
