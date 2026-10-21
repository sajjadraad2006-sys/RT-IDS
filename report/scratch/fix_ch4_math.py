with open('report/chapters/04-implementation-analysis.md', 'r', encoding='utf-8') as f:
    text = f.read()

bad_part = """The event hash $h_i$ is computed via SHA-256 over a strictly canonicalized JSON byte stream:
$$m_i = \\text{JSON}_{\\text{canon}}(t_i, a_i, \\alpha_i, \\tau_i, \\text{id}_i, p_i, h_{i-1})
h_i = \\mathcal{H}_{\\text{SHA-256}}(m_i) \\tag{4.12}

Canonicalization enforces lexicographically sorted keys and minimal token delimiters (`separators=(",", ":")`), ensuring that serialization whitespace variations cannot invalidate the digest.

Verification of chain integrity is performed by `verify_audit_chain()` `[CE-39]`. If an attacker directly alters a historical database row $E_k$ ($k < N$) or truncates intermediate records, the recalculation of $h_k$ diverges from the stored digest ($h_k 
eq \mathcal{H}_{\text{SHA-256}}(m_k)$), or the pointer equality breaks ($h_{k-1} 
eq E_k.\text{previous_hash}$), resulting in immediate verification failure:"""

good_part = """The event hash $h_i$ is computed via SHA-256 over a strictly canonicalized JSON byte stream:
$$m_i = \\text{JSON}_{\\text{canon}}(t_i, a_i, \\alpha_i, \\tau_i, \\text{id}_i, p_i, h_{i-1})$$
$$h_i = \\mathcal{H}_{\\text{SHA-256}}(m_i) \\tag{4.12}$$

Canonicalization enforces lexicographically sorted keys and minimal token delimiters (`separators=(",", ":")`), ensuring that serialization whitespace variations cannot invalidate the digest.

Verification of chain integrity is performed by `verify_audit_chain()` `[CE-39]`. If an attacker directly alters a historical database row $E_k$ ($k < N$) or truncates intermediate records, the recalculation of $h_k$ diverges from the stored digest ($h_k \\neq \\mathcal{H}_{\\text{SHA-256}}(m_k)$), or the pointer equality breaks ($h_{k-1} \\neq E_k.\\text{previous_hash}$), resulting in immediate verification failure:"""

if bad_part in text:
    text = text.replace(bad_part, good_part)
    with open('report/chapters/04-implementation-analysis.md', 'w', encoding='utf-8') as f:
        f.write(text)
    print('Fixed bad math in Chapter 4 successfully!')
else:
    print('Could not find bad_part exactly, searching dynamically...')
    idx = text.find('$$m_i =')
    end_idx = text.find('resulting in immediate verification failure:') + len('resulting in immediate verification failure:')
    print('Found section at', idx, end_idx)
    text = text[:idx] + good_part[good_part.find('$$m_i ='):] + text[end_idx:]
    with open('report/chapters/04-implementation-analysis.md', 'w', encoding='utf-8') as f:
        f.write(text)
    print('Dynamically replaced math block in Chapter 4.')
