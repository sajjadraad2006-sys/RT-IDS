with open('report/chapters/08-critical-evaluation.md', 'r', encoding='utf-8') as f:
    text = f.read()

old_q15 = """We have dedicated an entire chapter to this exact hazard in Chapter 9 (Section 9.4). In an industrial mechatronic cell, standard network containment (e.g., `iptables DROP`) is **strictly prohibited**. Cutting fieldbus communication while a 6-DOF robot arm is moving at high speed can cause severe collision with fixtures or uncoordinated gravitational dropping of heavy vertical axes. Therefore, our proposed mechatronic adaptation integrates directly with the certified Safety PLC via hardware fail-safe dry contacts, commanding an **IEC 60204-1 Category 1 Controlled Safe Stop** (controlled deceleration along the active trajectory before de-energizing drive power). Autonomous IT defense must never override physical functional safety interlocks."""

new_q15 = """We address this hazard in Chapter 9 (Section 9.4). In mechatronic workcells, abrupt network cutoffs (e.g., `iptables DROP`) risk mechanical collision or gravitational dropping of unbraked axes. Our proposed architecture subordinates active defense to certified Safety PLCs, commanding an **IEC 60204-1 Category 1 Controlled Safe Stop** (controlled deceleration along the active trajectory before removing motor power). Autonomous cybersecurity must never override physical safety interlocks."""

if old_q15 in text:
    text = text.replace(old_q15, new_q15)
    with open('report/chapters/08-critical-evaluation.md', 'w', encoding='utf-8') as f:
        f.write(text)
    print('Tightened Question 15 in Chapter 8 successfully!')
else:
    print('Could not find old_q15 text in Chapter 8!')
