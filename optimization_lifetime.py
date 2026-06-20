import gurobipy as gp
from gurobipy import GRB
import csv
import time

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

    with open("/home/nipuni/ns-allinone-3.35/ns-3.35/scratch/optimization_link_lifetime_data.csv",
              'r', encoding='UTF8') as csvfile:
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

            # Same node or out of radio range — no link
            if i == j or effective_distance >= d_max**2:
                lifetime.append(0.0)
                continue

            # Zero relative motion — link is stable, Gurobi would be unbounded
            dv2 = delta_vx[idx]**2 + delta_vy[idx]**2
            da2 = delta_ax[idx]**2 + delta_ay[idx]**2
            if dv2 < EPSILON and da2 < EPSILON:
                lifetime.append(STATIONARY_LIFETIME)
                continue

            # Normal case — solve with Gurobi
            m = gp.Model("link_lifetime")
            m.setParam('OutputFlag', 0)

            l     = m.addVar(lb=0.0, ub=GRB.INFINITY)
            lsqu  = m.addVar(lb=0.0, ub=GRB.INFINITY)
            lcub  = m.addVar(lb=0.0, ub=GRB.INFINITY)
            lquad = m.addVar(lb=0.0, ub=GRB.INFINITY)

            m.setObjective(l, GRB.MAXIMIZE)

            m.addGenConstrPow(l, lsqu,  2.0)
            m.addGenConstrPow(l, lcub,  3.0)
            m.addGenConstrPow(l, lquad, 4.0)

            term1 = (
                delta_px[idx]**2
                + delta_vx[idx]**2 * lsqu
                + 2 * delta_px[idx] * delta_vx[idx] * l
                + 0.25 * delta_ax[idx]**2 * lquad
                + delta_ax[idx] * delta_px[idx] * lsqu
                + delta_vx[idx] * delta_ax[idx] * lcub
            )
            term2 = (
                delta_py[idx]**2
                + delta_vy[idx]**2 * lsqu
                + 2 * delta_py[idx] * delta_vy[idx] * l
                + 0.25 * delta_ay[idx]**2 * lquad
                + delta_ay[idx] * delta_py[idx] * lsqu
                + delta_vy[idx] * delta_ay[idx] * lcub
            )

            m.addConstr(d_max**2 >= term1 + term2)
            m.optimize()

            if m.Status == GRB.OPTIMAL:
                lifetime.append(l.X)
            elif m.Status == GRB.INFEASIBLE:
                lifetime.append(0.0)
            else:
                # Unbounded or unexpected — treat as stable
                lifetime.append(STATIONARY_LIFETIME)

    with open("/home/nipuni/ns-allinone-3.35/ns-3.35/scratch/link_lifetime_solution.csv",
              'w', encoding='UTF8') as csvfile:
        writer = csv.writer(csvfile, delimiter=',', quotechar='"',
                            quoting=csv.QUOTE_MINIMAL)
        for i in range(n**2):
            s3 = "begin, " + str(float(lifetime[i])) + ", end"
            writer.writerow([s3])

    time2 = time.time() * 1000
    print("link lifetime optimization delay is %d ms" % (time2 - time1))

except gp.GurobiError as e:
    print('Error code ' + str(e.errno) + ': ' + str(e))

except Exception as e:
    print('Unexpected error in link lifetime optimization: ' + str(e))
