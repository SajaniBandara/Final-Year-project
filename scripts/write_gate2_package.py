import csv, json
from pathlib import Path
repo = Path(__file__).resolve().parent.parent
runs = list(csv.DictReader(open(repo / 'docs/gate2/gate2_runs.csv')))
acc = list(csv.DictReader(open(repo / 'docs/gate2/gate2_acceptance.csv')))
an = json.load(open(repo / 'docs/gate2/anchor_analysis.json'))
R = {r['run']: r for r in runs}
order = ['full_A1_enfoff','ab7abl_A1_enfoff','ab9abl_A1_enfoff','ab12abl_A1_enfoff','full_A3_enfoff','ab7abl_A3_enfoff','ab9abl_A3_enfoff','ab12abl_A3_enfoff','ab8abl_A3_enfoff']
t_off = "| run (detection only) | TP | FP | FN | TN | TP+FN | DR | FPR | M1 | per-cycle MCC ± 95 % CI | undefined cycles | FP by source | S3 raw |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|\n"
for t in order:
    x = R[t]
    t_off += f"| {t} | {x['TP']} | {x['FP']} | {x['FN']} | {x['TN']} | {x['TP+FN']} | {x['DR']} | {x['FPR']} | {x['M1']} | {x['cycleMCC']} ± {x['ci95']} | {x['undef_cycles']} | {x['fp_by_src']} | {x['S3_raw']} |\n"
on = [o.replace('enfoff', 'enfon') for o in order]
t_on = "| run (closed loop) | UFCR % (blocked / attempts) | legitimised | M4 prevention | M4 latency ms (n acted and contained) | M4 uncontained | M4 inf | M5 ms (failover events) | quarantines true/false | actions blocked |\n|---|---|---|---|---|---|---|---|---|---|\n"
for t in on:
    x = R[t]
    t_on += f"| {t} | {x['UFCR_pct']} ({x['blocked']}/{x['unauth']}) | {x['legitimised']} | {x['M4_prevention']} | {x['M4_latency_ms']} ({x['M4_n_acted_contained']}) | {x['M4_uncontained']} | {x['M4_inf']} | {x['M5_ms']} ({x['failover_events']}) | {x['quar_true/false']} | {x['blocked_actions']} |\n"
t_acc = "| check | result | numbers |\n|---|---|---|\n" + "".join(f"| {a['check']} | **{a['result']}** | {a['numbers']} |\n" for a in acc)
rows = []
for t, lab in (('anchor_lrad_enfoff', 'LRAD, detection only'), ('anchor_lrad_enfon', 'LRAD, closed loop')):
    for n in ('S1', 'S4'):
        r = an[t]['res'][n]
        rows.append(f"| {lab}: {n} | {r['rate_per_decision_post']*100:.2f} % ({r['raw_firings_post']} / {r['decisions_post']}) | {r['rate_per_nodecycle_post']*100:.2f} % ({r['alarm_nodecycles_post']} / 8,640) | {r['share_first60s']*100:.1f} % | {r['rsus_with_alarms']} RSUs; {r['rsus_for_80pct']} give 80 % |")
r = an['anchor_sfto']['res']['SFTO']
rows.append(f"| SFTO (own alarms; same run as LRAD) | n/a | {r['rate_per_nodecycle_post']*100:.2f} % ({r['alarm_nodecycles_post']} / 8,640) | {r['share_first60s']*100:.1f} % | {r['rsus_with_alarms']} RSUs; {r['rsus_for_80pct']} give 80 % |")
r = an['anchor_tap']['res']['TAP']
rows.append(f"| TAP (own run; raw decision) | {r['raw_firings_post']} violations after warm-up | {r['rate_per_nodecycle_post']*100:.2f} % ({r['alarm_nodecycles_post']} / 8,640) | {r['share_first60s']*100:.1f} % | {r['rsus_with_alarms']} RSUs; {r['rsus_for_80pct']} give 80 % |")
t_an = "| detector (benign p=0, 180 s) | false-alarm rate per decision (after 45 s) | per node-cycle (after 45 s) | share of alarms in first 60 s | concentration |\n|---|---|---|---|---|\n" + "\n".join(rows) + "\n"
tmpl = (repo / 'scripts/gate2_package_template.md').read_text()
out = tmpl.replace('@@ACC@@', t_acc).replace('@@OFF@@', t_off).replace('@@ON@@', t_on).replace('@@AN@@', t_an)
out = out.replace('@@LRAD_FPR@@', f"{an['anchor_lrad_enfoff']['FPR']*100:.1f} %").replace('@@TAP_FPR@@', f"{an['anchor_tap']['FPR']*100:.1f} %").replace('@@TAP_LIST@@', str(an['anchor_tap']['list_size']))
(repo / 'docs/GATE2_PACKAGE_2026-10-09.md').write_text(out)
print('written', len(out), 'chars')
