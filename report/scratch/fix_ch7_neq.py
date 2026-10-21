with open('report/chapters/07-security-and-safety-analysis.md', 'r', encoding='utf-8') as f:
    text = f.read()

# Fix split \neq lines
text = text.replace('h_k \neq h_{k-1}', 'h_k \\neq h_{k-1}')
text = text.replace('h_k \n eq h_{k-1}', 'h_k \\neq h_{k-1}')
text = text.replace('h_k \r\n eq h_{k-1}', 'h_k \\neq h_{k-1}')
text = text.replace('Mask}_{\\text{crit}} \n eq', 'Mask}_{\\text{crit}} \\neq')
text = text.replace('Mask}_{\\text{crit}} \r\n eq', 'Mask}_{\\text{crit}} \\neq')

# Dynamically search and fix in lines 235-245
lines = text.splitlines()
for i in range(len(lines)-1):
    if 'Adversary $\\mathcal{A}_2$' in lines[i] and 'eq h_{k-1}' in lines[i+1]:
        lines[i] = lines[i].rstrip() + " \\neq " + lines[i+1].replace("eq ", "").strip()
        lines[i+1] = ""
    if 'Quantifier-Free Bit-Vectors' in lines[i] and 'eq \\text{Subnet}' in lines[i+1]:
        lines[i] = lines[i].rstrip() + " \\neq " + lines[i+1].replace("eq ", "").strip()
        lines[i+1] = ""

clean_text = '\n'.join([l for l in lines if l != ""])
with open('report/chapters/07-security-and-safety-analysis.md', 'w', encoding='utf-8') as f:
    f.write(clean_text)
print('Cleaned Chapter 7 broken neq lines!')
