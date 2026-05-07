import gurobipy as gp
from gurobipy import GRB
import csv
import time

try:
	time1 = time.time()*1000
	max = 40
	n = 4
	ID = list()
	PX = list()
	PY = list()
	VX = list()
	VY = list()
	AX = list()
	AY = list()
	mobility_scenario = 1;
	d_max = 270

	with open("/home/nilmantha/ns-allinone-3.35/ns-3.35/scratch/optimization_link_lifetime_data.csv",'r',encoding='UTF8') as csvfile:
		csvreader = csv.reader(csvfile,delimiter=',',quotechar='"',quoting=csv.QUOTE_MINIMAL)
		
		for row in csvreader:
			p = str(row)
			q = p.split(", ")
			r =0
			for sh in q:
				if (r==0):
					n = int(sh[2:-1])
				elif (r==1):
					ID.append(int(sh[2:-1]))
				elif (r==2):
					PX.append(float(sh[2:-1]))
				elif (r==3):
					PY.append(float(sh[2:-1]))
				elif (r==4):
					VX.append(float(sh[2:-1]))		
				elif (r==5):
					VY.append(float(sh[2:-1]))
				elif (r==6):
					AX.append(float(sh[2:-1]))
				elif (r==7):
					AY.append(float(sh[2:-1]))
				elif (r==8):
					mobility_scenario = int(sh[2:-1])
				r = r + 1
		
	if (mobility_scenario == 0):
		d_max = 270
	
	if (mobility_scenario == 1):
		d_max = 270
	
	if (mobility_scenario == 2):
		d_max = 330
	
	"""
	print('n is %g \n' % (n))
	print(*(ID))
	print(*PX)
	print('scenario is %g \n' % (mobility_scenario))
	print(*(VX))
	"""
	
	csvfile.close();
		

	

	delta_px = list()
	delta_py = list()
	delta_vx = list()
	delta_vy = list()
	delta_ax = list()
	delta_ay = list()
	lifetime = list()
	for i in range(n):
		for j in range(n):
			delta_px.append(PX[i]-PX[j])
			delta_py.append(PY[i]-PY[j])
			delta_vx.append(VX[i]-VX[j])
			delta_vy.append(VY[i]-VY[j])
			delta_ax.append(AX[i]-AX[j])
			delta_ay.append(AY[i]-AY[j])
	#print(*(delta_px))
		
	for i in range(n):
		for j in range(n):
			effective_distance = (delta_px[(i*n)+j]*delta_px[(i*n)+j]) + (delta_py[(i*n)+j]*delta_py[(i*n)+j]) 
			if ((effective_distance >= (d_max**2)) | (i==j)):
				lifetime.append(0.0)
			else:
				
				m = gp.Model("link lifetime")
				# Create decision variables
				l = m.addVar(lb=0.0, ub=GRB.INFINITY)
				lsqu = m.addVar(lb=0.0, ub=GRB.INFINITY)
				lcub = m.addVar(lb=0.0, ub=GRB.INFINITY)
				lquad =  m.addVar(lb=0.0, ub=GRB.INFINITY)

				# Set objective function
				m.setObjective(l, gp.GRB.MAXIMIZE)
				

				# Add constraints
				m.addGenConstrPow(l, lsqu, 2.0)
				m.addGenConstrPow(l, lcub, 3.0)
				m.addGenConstrPow(l, lquad, 4.0)
				
				term1 = ((delta_px[(i*n)+j])*(delta_px[(i*n)+j]))+((delta_vx[(i*n)+j])*(delta_vx[(i*n)+j])*lsqu)+(2*(delta_px[(i*n)+j])*(delta_vx[(i*n)+j])*l)+(0.25*(delta_ax[(i*n)+j])*(delta_ax[(i*n)+j])*lquad)+((delta_ax[(i*n)+j])*(delta_px[(i*n)+j])*lsqu)+((delta_vx[(i*n)+j])*(delta_ax[(i*n)+j])*lcub)
				term2 = ((delta_py[(i*n)+j])*(delta_py[(i*n)+j]))+((delta_vy[(i*n)+j])*(delta_vy[(i*n)+j])*lsqu)+(2*(delta_py[(i*n)+j])*(delta_vy[(i*n)+j])*l)+(0.25*(delta_ay[(i*n)+j])*(delta_ay[(i*n)+j])*lquad)+((delta_ay[(i*n)+j])*(delta_py[(i*n)+j])*lsqu)+((delta_vy[(i*n)+j])*(delta_ay[(i*n)+j])*lcub)
		
				m.addConstr((d_max*d_max) >= ((term1)+(term2)))
				m.setParam('OutputFlag',0)
				# Solve it!
				m.optimize()

				#print(f"Optimal objective value: {m.objVal}")
				#print("Solution values: %s=%g" %(l.Varname, l.X))
				lifetime.append(l.X)
				
				#lifetime.append(1.0)
	
	with open("/home/nilmantha/ns-allinone-3.35/ns-3.35/scratch/link_lifetime_solution.csv",'w',encoding='UTF8') as csvfile:
		writer = csv.writer(csvfile,delimiter=',',quotechar='"',quoting=csv.QUOTE_MINIMAL)
		for i in range(n**2):
			s1 = str(float(lifetime[i]))
			s3 = "begin, " + s1 + ", " + "end"
			writer.writerow([s3])		
	csvfile.close();
	time2 = time.time()*1000
	delay = time2-time1
	print("delay is %d" %(delay))

except gp.GurobiError as e:
    print('Error code ' + str(e.errno) + ": " + str(e))

except AttributeError:
    print('Encountered an attribute error')
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
