"""
CyberGuard Ph.D. Research Program
Mathematical Equation Generator for IEEE Doctoral Monograph
Renders publication-grade mathematical equations using Matplotlib's MathText engine with Computer Modern fonts.
"""

import os
import matplotlib.pyplot as plt
from pathlib import Path


def render_equation(
    tex_str: str,
    out_path: str,
    eq_num: str = None,
    fontsize: float = 11.5,
    figsize: tuple = (7.1, 0.55),
    bg_color: str = "#F8FAFC",
    text_color: str = "#0F172A",
    num_color: str = "#334155",
):
    fig = plt.figure(figsize=figsize, dpi=300)
    fig.patch.set_facecolor(bg_color)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.axis("off")
    ax.patch.set_facecolor(bg_color)

    # If equation number is present, center the equation and right-align the number
    if eq_num:
        ax.text(
            0.45,
            0.5,
            tex_str,
            fontsize=fontsize,
            color=text_color,
            ha="center",
            va="center",
            math_fontfamily="cm",
        )
        ax.text(
            0.98,
            0.5,
            eq_num,
            fontsize=fontsize - 0.5,
            color=num_color,
            ha="right",
            va="center",
            fontfamily="serif",
        )
    else:
        ax.text(
            0.5,
            0.5,
            tex_str,
            fontsize=fontsize,
            color=text_color,
            ha="center",
            va="center",
            math_fontfamily="cm",
        )

    plt.savefig(
        out_path,
        bbox_inches="tight",
        pad_inches=0.06,
        facecolor=bg_color,
    )
    plt.close(fig)


def generate_all_monograph_equations(out_dir: str = "docs/figures/equations"):
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    equations = [
        # Invariant 1
        {
            "tex": r"$\forall a \in \mathcal{A}_{\mathrm{cand}},\quad \mathrm{Target}(a) \cap \mathcal{K}_{\mathrm{crit}} = \emptyset \quad\wedge\quad \mathrm{IPv6\_Unmap}(\mathrm{Target}(a)) \notin \mathcal{K}_{\mathrm{crit}}$",
            "file": "eq1_inv1.png",
            "num": "(1)",
            "size": (6.8, 0.55),
        },
        # Invariant 1 Core Set Definition
        {
            "tex": r"$\mathcal{K}_{\mathrm{crit}} = \mathcal{H}_{\mathrm{core}} \cup \mathcal{N}_{\mathrm{core}} \cup \mathcal{P}_{\mathrm{core}} = \{ \mathrm{DC},\, \mathrm{DNS},\, \mathrm{GW},\, \mathrm{Loopback},\, \mathrm{CoreOS\_Procs} \}$",
            "file": "eq1_inv1_set.png",
            "num": None,
            "size": (6.8, 0.45),
        },
        # Invariant 2
        {
            "tex": r"$\forall a \in \mathcal{A}_{\mathrm{cand}},\quad \mathrm{Type}(a) \in \Omega_{\mathrm{D3FEND}} \;\wedge\; \mathrm{MetaChars}(\mathrm{Target}(a)) = \emptyset \;\wedge\; \mathrm{Valid}(\mathrm{Params}(a))$",
            "file": "eq2_inv2.png",
            "num": "(2)",
            "size": (6.8, 0.55),
        },
        # Invariant 3
        {
            "tex": r"$\forall a \in \mathcal{A}_{\mathrm{admitted}},\quad \exists\, \sigma_a \;\Rightarrow\; \mathrm{Rollback}(a, \sigma_a) \equiv \mathrm{State}_{\mathrm{pre}}(t)$",
            "file": "eq3_inv3.png",
            "num": "(3)",
            "size": (6.8, 0.55),
        },
        # Invariant 3 HMAC token
        {
            "tex": r"$\sigma_a = \mathrm{HMAC}_{\kappa}\left( \mathrm{ActionID}(a) \;|\; \mathrm{Target}(a) \;|\; \mathrm{Params}(a) \;|\; t_{\mathrm{exec}} \;|\; \mathrm{nonce} \right)$",
            "file": "eq3_inv3_hmac.png",
            "num": None,
            "size": (6.8, 0.45),
        },
        # Invariant 4
        {
            "tex": r"$\mathcal{D}(a) \leq \alpha \cdot \mathcal{S}(t) \cdot \mathcal{C}(m), \qquad \text{where } \alpha = 1.25, \quad \mathcal{D}(a) \in [0, 1]$",
            "file": "eq4_inv4.png",
            "num": "(4)",
            "size": (6.8, 0.55),
        },
        # RRF Dual-Channel Fusion
        {
            "tex": r"$\mathrm{RRF}(d) = \frac{w_A}{k + r_A(d)} + \frac{w_B}{k + r_B(d)} + \gamma \cdot \mathbb{I}_{\mathrm{hypergraph}}(d)$",
            "file": "eq5_rrf.png",
            "num": "(5)",
            "size": (6.8, 0.55),
        },
        # Pareto Multi-Objective Frontier
        {
            "tex": r"$\max_{a \in \mathcal{A}_{\mathrm{cand}}} \; J(a) = \lambda \cdot \mathcal{C}(a) - (1 - \lambda) \cdot \mathcal{D}(a) \quad \text{subject to } \quad \mathcal{D}(a) \leq B_{\mathrm{max}} = 0.50$",
            "file": "eq6_pareto.png",
            "num": "(6)",
            "size": (6.8, 0.55),
        },
        # Adversarial Resilience & MTTC
        {
            "tex": r"$\mathrm{ARR} = 1 - \frac{1}{|\mathcal{P}|} \sum_{p \in \mathcal{P}} \mathbb{I}(\mathrm{Evaded}(p)), \qquad \mathrm{MTTC} = \frac{1}{|\mathcal{E}|} \sum_{e \in \mathcal{E}} (t_{\mathrm{contain}}(e) - t_{\mathrm{detect}}(e))$",
            "file": "eq7_metrics.png",
            "num": "(7)",
            "size": (6.8, 0.55),
        },
    ]

    for item in equations:
        out_file = os.path.join(out_dir, item["file"])
        render_equation(
            tex_str=item["tex"],
            out_path=out_file,
            eq_num=item["num"],
            figsize=item["size"],
        )
        print(f"Generated: {out_file} ({os.path.getsize(out_file)} bytes)")


if __name__ == "__main__":
    generate_all_monograph_equations()
