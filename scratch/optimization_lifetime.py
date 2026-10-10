import argparse
import os
import sys
import gurobipy as gp
from gurobipy import GRB
import csv
import time
import math

parser = argparse.ArgumentParser()
parser.add_argument('--tag', default='', help='Run tag appended to CSV filenames')
args = parser.parse_args()
TAG = args.tag
RESULTS_DIR = "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/"

SCRATCH          = "/home/sdvn_hidden_attacks/ns3_g13/ns-allinone-3.35/ns-3.35/scratch/"
INPUT_CSV        = SCRATCH + "optimization_link_lifetime_data" + TAG + ".csv"
OUTPUT_CSV       = SCRATCH + "link_lifetime_solution"          + TAG + ".csv"

STATIONARY_LIFETIME = 100.0
EPSILON = 1e-9

try:
    time1 = time.time() * 1000
    n = 4
    ID = []
    PX = []
    PY = []
    VX = []
    VY = []
    AX = []
    AY = []
    mobility_scenario = 1
    d_max = 270

    with open(INPUT_CSV, 'r', encoding='UTF8') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',', quotechar='"',
                               quoting=csv.QUOTE_MINIMAL)
        for row in csvreader:
            p = str(row)
            q = p.split(", ")
            for r, sh in enumerate(q):
                val = sh[2:-1]
                if   r == 0: n                 = int(val)
                elif r == 1: ID.append(int(val))
                elif r == 2: PX.append(float(val))
                elif r == 3: PY.append(float(val))
                elif r == 4: VX.append(float(val))
                elif r == 5: VY.append(float(val))
                elif r == 6: AX.append(float(val))
                elif r == 7: AY.append(float(val))
                elif r == 8: mobility_scenario = int(val)

    if   mobility_scenario == 0: d_max = 270
    elif mobility_scenario == 1: d_max = 270
    elif mobility_scenario == 2: d_max = 330

    # Step-1 input checks (supervisor 2026-10-08): refuse non-finite state, count what reaches the optimiser.
    active = [ID[i] >= 0 for i in range(n)]
    for i in range(n):
        if active[i] and not all(math.isfinite(x) for x in (PX[i], PY[i], VX[i], VY[i], AX[i], AY[i])):
            print('[SOLVER-ERROR] non-finite state for node %d' % i, file=sys.stderr)
            sys.exit(3)
    n_inactive_pairs = n_out_of_range = n_stationary = n_optimised = 0
    status_count = {}
    nonopt_rows = []

    delta_px, delta_py = [], []
    delta_vx, delta_vy = [], []
    delta_ax, delta_ay = [], []

    for i in range(n):
        for j in range(n):
            delta_px.append(PX[i] - PX[j])
            delta_py.append(PY[i] - PY[j])
            delta_vx.append(VX[i] - VX[j])
            delta_vy.append(VY[i] - VY[j])
            delta_ax.append(AX[i] - AX[j])
            delta_ay.append(AY[i] - AY[j])

    lifetime = []

    for i in range(n):
        for j in range(n):
            idx = i * n + j

            effective_distance = delta_px[idx]**2 + delta_py[idx]**2

            if i == j:
                lifetime.append(0.0)
                continue
            # Inactive (not yet reporting / departed) node: no links
            if not (active[i] and active[j]):
                n_inactive_pairs += 1
                lifetime.append(0.0)
                continue
            # Out of radio range — no link
            if effective_distance >= d_max**2:
                n_out_of_range += 1
                lifetime.append(0.0)
                continue

            # Zero relative motion — link is stable, Gurobi would be unbounded
            dv2 = delta_vx[idx]**2 + delta_vy[idx]**2
            da2 = delta_ax[idx]**2 + delta_ay[idx]**2
            if dv2 < EPSILON:
                n_stationary += 1
                lifetime.append(STATIONARY_LIFETIME)
                continue

            # Normal case -- solve with Gurobi. Constant-velocity model (supervisor 2026-10-08: acceleration
            # term removed, s = s0 + v t). The in-range condition |dp + dv t|^2 <= d_max^2 is a convex
            # quadratic in t, so the link lifetime is its largest feasible t: a 1-variable convex QCP.
            n_optimised += 1
            m = gp.Model("link_lifetime")
            m.setParam('OutputFlag', 0)
            # Threads=1: gurobi defaults to every core; with several sims running that oversubscribed the host
            # (load ~97) and one call stalled for an hour. TimeLimit guards any pathological pair.
            m.setParam('Threads', 1)
            m.setParam('TimeLimit', 5)

            l = m.addVar(lb=0.0, ub=GRB.INFINITY)
            m.setObjective(l, GRB.MAXIMIZE)
            m.addQConstr(dv2 * l * l + 2 * (delta_px[idx] * delta_vx[idx] + delta_py[idx] * delta_vy[idx]) * l
                         + effective_distance <= d_max**2)
            m.optimize()

            status_count[m.Status] = status_count.get(m.Status, 0) + 1
            # Closed form of the same convex problem (largest t with |dp + dv t|^2 <= d_max^2), used ONLY to
            # verify a non-OPTIMAL incumbent -- never as a substitute for the solver.
            _b = delta_px[idx] * delta_vx[idx] + delta_py[idx] * delta_vy[idx]
            _cf = (-_b + math.sqrt(max(_b * _b - dv2 * (effective_distance - d_max ** 2), 0.0))) / dv2
            if m.Status == GRB.OPTIMAL:
                lifetime.append(l.X)
            elif m.Status in (GRB.SUBOPTIMAL, GRB.TIME_LIMIT) and m.SolCount > 0:
                _rel = abs(l.X - _cf) / max(_cf, 1.0)
                nonopt_rows.append((m.Status, i, j, l.X, _cf, _rel))
                if _rel > 1e-3:   # incumbent disagrees with the closed form: stop, do not guess
                    print('[SOLVER-ERROR] non-optimal status %d for pair (%d,%d): l=%g closed form=%g' % (m.Status, i, j, l.X, _cf), file=sys.stderr)
                    sys.exit(3)
                lifetime.append(l.X)
            else:
                # INFEASIBLE cannot happen (l = 0 is feasible for an in-range pair); UNBOUNDED cannot happen (dv2 > 0).
                # No silent fallback: any other status stops the run.
                print('[SOLVER-ERROR] unexpected Gurobi status %d for pair (%d,%d)' % (m.Status, i, j), file=sys.stderr)
                sys.exit(3)
            m.dispose()   # ~5,000 models per call: free the native memory now (a rare interpreter corruption was seen in-simulation)

    if n_optimised == 0:
        print('[SOLVER-ERROR] no node pair reached the optimiser (inactive=%d out_of_range=%d stationary=%d)'
              % (n_inactive_pairs, n_out_of_range, n_stationary), file=sys.stderr)
        sys.exit(3)

    with open(OUTPUT_CSV, 'w', encoding='UTF8') as csvfile:
        writer = csv.writer(csvfile, delimiter=',', quotechar='"',
                            quoting=csv.QUOTE_MINIMAL)
        for i in range(n**2):
            s3 = "begin, " + str(float(lifetime[i])) + ", end"
            writer.writerow([s3])

    try:   # diagnostics only: a failure here must never cost the solution that was just written
        _stats = RESULTS_DIR + "solver_pairs" + TAG + ".csv"
        _new = not os.path.exists(_stats)
        with open(_stats, "a") as sf:
            if _new:
                sf.write("t_wall_ms,n_nodes,n_active,inactive_pairs,out_of_range,stationary,optimised,st_optimal,st_suboptimal,st_other,mean_lt_inrange,median_lt_inrange,mean_lt_optimised,median_lt_optimised\n")
            import statistics as _st
            _inr = [x for x in lifetime if x > 0.0]
            _opt = [x for x in lifetime if 0.0 < x != STATIONARY_LIFETIME]
            _f = lambda v, fn: (fn(v) if v else 0.0)
            sf.write("%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%.3f,%.3f,%.3f,%.3f\n" % (int(time.time()*1000 - time1), n, sum(active),
                     n_inactive_pairs, n_out_of_range, n_stationary, n_optimised,
                     status_count.get(GRB.OPTIMAL, 0), status_count.get(GRB.SUBOPTIMAL, 0),
                     n_optimised - status_count.get(GRB.OPTIMAL, 0) - status_count.get(GRB.SUBOPTIMAL, 0),
                     _f(_inr, _st.mean), _f(_inr, _st.median), _f(_opt, _st.mean), _f(_opt, _st.median)))
        if nonopt_rows:
            _no = RESULTS_DIR + "solver_nonoptimal" + TAG + ".csv"
            _newf = not os.path.exists(_no)
            with open(_no, "a") as nf:
                if _newf: nf.write("status,i,j,gurobi_l,closed_form,rel_err\n")
                for r_ in nonopt_rows: nf.write("%d,%d,%d,%.9g,%.9g,%.3g\n" % r_)
    except Exception:
        import traceback; traceback.print_exc()

    time2 = time.time() * 1000
    print("link lifetime optimization delay is %d ms" % (time2 - time1))

    # Record which solver produced this run's lifetimes (supervisor request 2026-10-08: no silent
    # fallback, and every output set must say which solver ran).
    _used = RESULTS_DIR + "solver_used" + TAG + ".txt"
    _n = 0
    try:
        _n = int(open(_used).read().split("calls=")[1].split()[0])
    except Exception:
        _n = 0
    open(_used, "w").write("solver=gurobi version=%s license=%s python=%s script=%s calls=%d\n" % (
        ".".join(str(x) for x in gp.gurobi.version()), os.environ.get("SDVN_GUROBI_LICENSE", "file"),
        sys.executable, os.path.basename(__file__), _n + 1))

except gp.GurobiError as e:
    # No silent fallback: a solver failure must stop the run (non-zero exit is checked by routing.cc).
    print('[SOLVER-ERROR] Gurobi error ' + str(e.errno) + ': ' + str(e), file=sys.stderr)
    sys.exit(3)

except Exception as e:
    import traceback
    print('[SOLVER-ERROR] Unexpected error in link lifetime optimization: ' + str(e), file=sys.stderr)
    traceback.print_exc()          # always show WHERE (a rare, non-reproducible failure killed one run at t=157 s)
    sys.exit(3)
