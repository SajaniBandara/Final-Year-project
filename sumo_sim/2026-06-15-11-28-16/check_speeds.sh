#!/bin/bash
python3 -c "
import xml.etree.ElementTree as ET
import sys
tree = ET.parse(sys.argv[1])
speeds = []
for edge in tree.findall('edge'):
    if edge.get('function') == 'internal':
        continue
    for lane in edge.findall('lane'):
        s = lane.get('speed')
        disallow = lane.get('disallow', '')
        if 'passenger' in disallow:
            continue
        if s:
            speeds.append(float(s))
speeds.sort()
n = len(speeds)
print(f'Usable lanes: {n}')
print(f'Max: {speeds[-1]*3.6:.1f} km/h')
print(f'Median: {speeds[n//2]*3.6:.1f} km/h')
print(f'% >= 60km/h: {sum(1 for s in speeds if s>=16.67)/n*100:.1f}')
print(f'% >= 50km/h: {sum(1 for s in speeds if s>=13.89)/n*100:.1f}')
print(f'% >= 40km/h: {sum(1 for s in speeds if s>=11.11)/n*100:.1f}')
" "$1"
