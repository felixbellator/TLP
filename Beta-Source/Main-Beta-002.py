#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import datetime
from prettytable import PrettyTable
from sys import exit
from datetime import timedelta
import argparse
import csv
import numpy as np

#Variables Declare
sC = 0
drill_IP = ''
line_count = 0
count = 0
i = 0
j = 0
n = 0
x = 0 
y = 0
rows = 0
final_count = 0
l = 0
byt = 0
final_ip = ''
app = ''
ip = ''
dst = ''
ip_src = []
ip_dst = []
unique = []
src = []
d = []
ip_list = []
appl = []
byte_count = []
result = [[],[]]
dest = [[],[]]


# WIZARD MODE Functions - Reusable for other modes.

#Source Mode functions - Wizard Mode:

#Source Mode - Tree Opotion 1

def STSource(file, t):
	line_count = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				ip_src.append(row[7])
				line_count += 1	
		print(f'Processed {line_count} lines.\n')
		print(f'Adding to Unique and counting occurrence\n')
		unique, count = np.unique(ip_src, return_counts=True)
		result = list(zip(unique, count))
		length = int(len(result))	
		result_table=PrettyTable(['#','Source','Count'])
		result.sort(key=lambda result: result[1], reverse=True)
		if length <= t:
			print(f'Number of unique entries is less than this value!! Only {length} unique values are available !!\n')
			print(f'Running search for the Top {length} entries instead\n')
			for i in range(length):
				result_table.add_row([i+1, result[i][0], result[i][1]])
		else:
			for i in range(t):
				result_table.add_row([i+1, result[i][0], result[i][1]])
	return result_table

#Source Mode - Tree Option 1.1

def STDrilldestination(drill_IP,file,top):	
	src1 = []
	dest1 = [[],[]]
	x = 0
	l = 0
	result_table=PrettyTable(['#','Source','Destination','Count'])
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if str(drill_IP)==row[7]:
				src1.append(row[8])
		d1, count1 = np.unique(src1, return_counts=True)
		dest1 = list(zip(d1, count1))
		if int(len(dest1)) < top:
			top = int(len(dest1))
			print(f'Not enough unique entries!! Seaching for {top} entries instead.')
		print(f'\nIdentifying the Top {top} destinations of source {drill_IP}\n')
		dest1.sort(key=lambda dest1: dest1[1], reverse=True)
		for i in range(int(top)):
			result_table.add_row([i+1, drill_IP, dest1[i][0], dest1[i][1]])
	dest1 = [[],[]]
	src1 = []
	return result_table

#Source Mode - Treee Option 1.2 (both 1.2.1 & 1.2.2 are described in the same function)

def STDrillApplication(file,source,top,opt):
	result = [[],[]]
	appl = []
	interim_result = [[],[]]
	byte_count = []
	line_count = 0
	byt = []
	b = 0	
	n = 0
	j = 0
	index = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if str(row[7]) == source:
					appl.append(row[14])
					byte_count.append(row[31])
					line_count += 1
		if opt == 'b':
			result_table = PrettyTable(['#','Source IP Address','Application','Total Bytes'])
			interim_result = list(zip(appl,byte_count))
			appl = np.unique(appl)
			for app in appl:
				for row in interim_result:
					if row[0] == app:
						b += int(row[1])
				byt.append(b)
			result = list(zip(appl,byt))
			result.sort(key=lambda result: result[1], reverse=True)
			if int(len(result) < top):
				print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
				top = int(len(result))
			for i in range(top):
				result_table.add_row([i+1,source,result[i][0],result[i][1]])
			print(f'\nTop Applications Done by Byte Count!!\n')
		elif opt == 's':
			app, count = np.unique(appl, return_counts=True)
			result = list(zip(app,count))
			result.sort(key=lambda result: result[1], reverse=True)
			result_table = PrettyTable(['#','Source IP Address','Application','Session Count'])
			if int(len(result) < top):
				print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
				top = int(len(result))
			for i in range(top):
				result_table.add_row([i+1,source,result[i][0],result[i][1]])
			print(f'\nTop Applications Done by Session Count!!\n')
	return result_table

# Source Wizard Mode modules done
#
#
# Destination Wizard mode modules described below, starting with 2 - 2.2.2
# Destination Mode Tree option 2

def DTDestination(file, top):
	line_count = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				ip_src.append(row[8])
				line_count += 1	
		print(f'Processed {line_count} lines.')
		print(f'Adding to Unique and counting occurrence')
		unique, count = np.unique(ip_src, return_counts=True)
		result = list(zip(unique, count))
		result_table=PrettyTable(['#','Destination IP address','Count'])
		result.sort(key=lambda result: result[1], reverse=True)
		#Identify TOP Sources
		if int(len(result)) <= top:
			print(f'Number of unique entries is less than this value!! Only {length} unique values are available !!\n')
			print(f'Running search for the Top {length} entries instead\n')
			top = int(len(result))
		for i in range(top):
			result_table.add_row([i+1, result[i][0], result[i][1]])
	return result_table

#Destination Mode Tree option 2.1 - Top Destination with Drill-down Source

def DTDrillsource(file,drill_IP,top):	
	dst1 = []
	src1 = [[],[]]
	x = 0
	l = 0
	result_table=PrettyTable(['#','Source','Destination','Count'])
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if str(drill_IP)==row[8]:
				dst1.append(row[7])
		s1, count1 = np.unique(dst1, return_counts=True)
		src1 = list(zip(s1, count1))
		src1.sort(key=lambda src1: src1[1], reverse=True)
		if int(len(src1)) < top:
			top = int(len(src1))
			print(f'Not enough unique entries!! Seaching for {top} entries instead.')
		print(f'\nIdentifying the Top {top} Sources for Destination {drill_IP}\n')
		for i in range(top):
			result_table.add_row([i+1, src1[i][0],drill_IP, src1[i][1]])
	print(f'Sources done for {drill_IP}')
	dest1 = [[],[]]
	src1 = []
	return result_table

#Destination Mode Tree option 2.2.1 - 2.2.2 - Top Application by Bytes or Sessions (defined in the same function)

def DTDrillApplication(file,destination,top,opt):
	result = [[],[]]
	appl = []
	interim_result = [[],[]]
	byte_count = []
	line_count = 0
	byt = []
	b = 0	
	n = 0
	j = 0
	index = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if str(row[8]) == destination:
					appl.append(row[14])
					byte_count.append(row[31])
					line_count += 1
		if opt == 'b':
			result_table = PrettyTable(['#','Destination IP Address','Application','Total Bytes'])
			interim_result = list(zip(appl,byte_count))
			appl = np.unique(appl)
			for app in appl:
				for row in interim_result:
					if row[0] == app:
						b += int(row[1])
				byt.append(b)
			result = list(zip(appl,byt))
			result.sort(key=lambda result: result[1], reverse=True)
			if int(len(result) < top):
				print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
				top = int(len(result))
			for i in range(top):
				result_table.add_row([i+1,destination,result[i][0],result[i][1]])
			print(f'\nTop Applications Done by Byte Count!!\n')
		elif opt == 's':
			app, count = np.unique(appl, return_counts=True)
			result = list(zip(app,count))
			result.sort(key=lambda result: result[1], reverse=True)
			result_table = PrettyTable(['#','Source IP Address','Application','Session Count'])
			if int(len(result) < top):
				print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
				top = int(len(result))
			for i in range(top):
				result_table.add_row([i+1,destination,result[i][0],result[i][1]])
			print(f'\nTop Applications Done by Session Count!!\n')
	return result_table

# Destination Mode Modules done.

##
##

# Top Applications Mode - Tree option 3

# Top Application Mode by bytes 

def ATBApplication(file,top):
	line_count = 0
	appl, byt = [], []
	byte_count = []
	b = 0
	j = 0 
	n = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				appl.append(row[14])
				byte_count.append(row[31])
				line_count += 1
		interim_result = list(zip(appl,byte_count))
		appl = np.unique(appl)
		for app in appl:
			for row in interim_result:
				if row[0] == app:
					b += int(row[1])
			byt.append(b)
		result = list(zip(appl,byt))
		result_table=PrettyTable(['#','Application','Count'])
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result)) <= top:
			print(f'Number of unique entries is less than this value!! Only {length} unique values are available !!\n')
			print(f'Running search for the Top {length} entries instead\n')
			top = int(len(result))
		for i in range(top):
			result_table.add_row([i+1, result[i][0], result[i][1]])
	print(f'\nTop Applications Done by Byte Count!!\n')
	return result_table

#Top Application Mode by bytes - Source Drill-down - Tree option 3.2

def ATBDrillSource(file,ApDrill,top):
	line_count = 0
	src, byt = [], []
	byte_count = []
	b = 0
	j = 0 
	n = 0
	result_table=PrettyTable(['#','Application','Source','Count'])
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if row[14] == ApDrill:
					src.append(row[7])
					byte_count.append(row[31])
					line_count += 1
		interim_result = list(zip(src,byte_count))
		print(f'{line_count} lines processed.')
		src = np.unique(src)
		print(f'Unqie entries = {int(len(src))}')
		for a in src:
			for row in interim_result:
				if row[0] == a:
					b += int(row[1])
			byt.append(b)
		result = list(zip(src,byt))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < top):
			top = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {top} instead')
		for i in range(top):
			result_table.add_row([i+1, ApDrill, result[i][0], result[i][1]])
	print(f'\nTop Source Drll-down Done by Byte Count!!\n')
	return result_table


#Wizard Mode Function - Top Application given a specific destination that was accessed - tree option 3.4

def ATBDrillDestination(file,ApDrill,top):
	line_count = 0
	dst, byt = [], []
	byte_count = []
	b = 0
	j = 0 
	n = 0
	result_table=PrettyTable(['#','Application','Destination Address','Count'])
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if row[14] == ApDrill:
					dst.append(row[8])
					byte_count.append(row[31])
					line_count += 1
		interim_result = list(zip(dst,byte_count))
		print(f'{line_count} lines processed.')
		dst = np.unique(dst)
		for a in dst:
			for row in interim_result:
				if row[0] == a:
					b += int(row[1])
			byt.append(b)
		result = list(zip(dst,byt))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < top):
			top = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {top} instead')
		for i in range(top):
			result_table.add_row([i+1, ApDrill, result[i][0], result[i][1]])
	print(f'\nTop Source Drll-down Done by Byte Count!!\n')
	return result_table

##
##
#Wizard-Mode - Top Applications by SessionCount - Tree option 3

def ATSApplication(file, top):
	line_count = 0
	appl, byt = [], []
	count = []
	b = 0
	j = 0 
	n = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				appl.append(row[14])
				line_count += 1
		appl, count = np.unique(appl, return_counts=True)
		result = list(zip(appl,count))
		result.sort(key=lambda result: result[1], reverse=True)
		result_table = PrettyTable(['#','Application','Session Count'])
		if int(len(result) < top):
			top = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {re} instead')
		for i in range(top):
			result_table.add_row([i+1, result[i][0], result[i][1]])
	print(f'\nTop Applications Done by Session Count!!\n')
	return result_table

# Wizard Mode - Top Source for a given application by Session Count - Tree option 3.1

def ATSDrillSource(file,ApDrill,top):
	line_count = 0
	src, byt = [], []
	count = []
	b = 0
	j = 0 
	n = 0
	result_table=PrettyTable(['#','Application','Source','Count'])
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if row[14] == ApDrill:
					src.append(row[7])
					line_count += 1
		src, count = np.unique(src, return_counts=True)
		print(f'Unqie entries = {int(len(src))}')
		result = list(zip(src,count))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < top):
			top = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {top} instead')
		for i in range(top):
			result_table.add_row([i+1, ApDrill, result[i][0], result[i][1]])
	print(f'\nTop Source Drll-down Done by Session Count!!\n')
	return result_table

# Wizard Mode - Top Destination for a give application by Session Count - Tree option 3.3

def ATSDrillDestination(file,ApDrill,top):
	line_count = 0
	dst, byt = [], []
	count = []
	b = 0
	j = 0 
	n = 0
	result_table=PrettyTable(['#','Application','Destination','Count'])
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if row[14] == ApDrill:
					dst.append(row[8])
					line_count += 1
		dst, count = np.unique(dst, return_counts=True)
		result = list(zip(dst,count))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < top):
			top = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {top} instead')
		for i in range(top):
			result_table.add_row([i+1, ApDrill, result[i][0], result[i][1]])
	print(f'\nTop Destination Drll-down Done by Session Count!!\n')
	return result_table


# WIZARD/COMMON-MODE definitions are done.

###################################################################################################
###################################################################################################

#QUICK_MODE Definitions:

# Quick-TOP Source Mode

def QSTSource(file, t):
	line_count = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				ip_src.append(row[7])
				line_count += 1	
		print(f'Processed {line_count} lines.\n')
		print(f'Adding to Unique and counting occurrence\n')
		unique, count = np.unique(ip_src, return_counts=True)
		result = list(zip(unique, count))
		length = int(len(result))
		result.sort(key=lambda result: result[1], reverse=True)
		if length <= t:
			print(f'Number of unique entries is less than this value!! Only {length} unique values are available !!\n')
			print(f'Running search for the Top {length} entries instead\n')
			result = result[:length]
		else:
			result = result[:t]
	return result

#Quick-Mode TOP Source - Drill down Destination - Mode

def QSTDrilldestination(drill_IP,file,top):	
	dest1 = []
	src1 = [[],[]]
	x = 0
	l = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if str(drill_IP)==row[7]:
				dest1.append(row[8])
		d1, count1 = np.unique(dest1, return_counts=True)
		src1 = list(zip(d1, count1))
		src1.sort(key=lambda src1: src1[1], reverse=True)
		if int(len(src1)) < top:
			top = int(len(src1))
			print(f'\nNot enough unique entries!! Seaching for {top} entries instead.\n')
		src1 = src1[:top]
	return src1

# Quick-Mode TOP sources - Drill down application - Sorted by bytes

def QSTDrillApplicationByte(source,file, req):
	result = [[],[]]
	appl = []
	interim_result = [[],[]]
	byte_count = []
	line_count = 0
	byt = []
	b = 0	
	n = 0
	j = 0
	index = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if str(row[7]) == source:
					appl.append(row[14])
					byte_count.append(row[31])
					line_count += 1
		interim_result = list(zip(appl,byte_count))
		appl = np.unique(appl)
		for app in appl:
			for row in interim_result:
				if row[0] == app:
					b += int(row[1])
			byt.append(b)
		result = list(zip(appl,byt))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < req):
			print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
			result = result[:int(len(result))]
		else:
			result = result[:req]
		print(f'\nTop Applications Done by Byte Count!!\n')
	return result

# Quick-Mode TOP sources - Drill down application - Sorted by sessions

def QSTDrillApplicationSession( source, file, req):
	result = [[],[]]
	appl = []
	interim_result = [[],[]]
	byte_count = []
	line_count = 0
	byt = []
	b = 0	
	n = 0
	j = 0
	index = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if str(row[7]) == source:
					appl.append(row[14])
					byte_count.append(row[31])
					line_count += 1
		app, count = np.unique(appl, return_counts=True)
		result = list(zip(app,count))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < req):
			print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
			result = result[:int(len(result))]
		else:
			result = result[:req]
		print(f'\nTop Applications Done by Session Count!!\n')
	return result

# Quick-Mode - Top Destinations 

def QDTDestination(file, t):
	line_count = 0
	result = []
	ip_src = []
	result.clear()
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
				ip_src.append(row[8])
				line_count += 1	
		print(f'Processed {line_count} lines.\n')
		print(f'Adding to Unique and counting occurrence\n')
		unique, count = np.unique(ip_src, return_counts=True)
		result = list(zip(unique, count))
		length = int(len(result))
		result.sort(key=lambda result: result[1], reverse=True)
		if length <= t:
			print(f'Number of unique entries is less than this value!! Only {length} unique values are available !!\n')
			print(f'Running search for the Top {length} entries instead\n')
			result = result[:length]
		else:
			result = result[:t]
		print(f'{result}')
	return result

#Quiick-Mode - Top Destinations - Drill - down source

def QDTDrillSource(drill_IP,file,top):	
	src1 = []
	dest1 = [[],[]]
	x = 0
	l = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if str(drill_IP)==row[8]:
				src1.append(row[7])
		d1, count1 = np.unique(src1, return_counts=True)
		dest1 = list(zip(d1, count1))
		dest1.sort(key=lambda dest1: dest1[1], reverse=True)
		if int(len(dest1)) < top:
			top = int(len(dest1))
			print(f'\nNot enough unique entries!! Seaching for {top} entries instead.\n')
		dest1 = dest1[:top]
	return dest1

# Quick-Mode - Top Destinations - Drill -down Application - Sorted by session count

def QDTDrillApplicationSession( dest, file, req):
	result = [[],[]]
	appl = []
	interim_result = [[],[]]
	byte_count = []
	line_count = 0
	byt = []
	b = 0	
	n = 0
	j = 0
	index = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if str(row[8]) == dest:
					appl.append(row[14])
					byte_count.append(row[31])
					line_count += 1
		app, count = np.unique(appl, return_counts=True)
		result = list(zip(app,count))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < req):
			print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
			result = result[:int(len(result))]
		else:
			result = result[:req]
		print(f'\nTop Applications Done by Session Count!!\n')
	return result

#Quick-Mode - Top Destination - Drill-down Application - sorted by byte count

def QDTDrillApplicationByte(dest,file, req):
	result = [[],[]]
	appl = []
	interim_result = [[],[]]
	byte_count = []
	line_count = 0
	byt = []
	b = 0	
	n = 0
	j = 0
	index = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if str(row[8]) == dest:
					appl.append(row[14])
					byte_count.append(row[31])
					line_count += 1
		interim_result = list(zip(appl,byte_count))
		appl = np.unique(appl)
		for app in appl:
			for row in interim_result:
				if row[0] == app:
					b += int(row[1])
			byt.append(b)
		result = list(zip(appl,byt))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < req):
			print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
			result = result[:int(len(result))]
		else:
			result = result[:req]
		print(f'\nTop Applications Done by Byte Count!!\n')
	return result

## Quick-Application Mode

##
##
# Quick Application Mode - Top Application L1 - Sort By Byte Count:

def QATBApplication(file,top):
	line_count = 0
	appl, byt = [], []
	byte_count = []
	b = 0
	j = 0 
	n = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				appl.append(row[14])
				byte_count.append(row[31])
				line_count += 1
		interim_result = list(zip(appl,byte_count))
		appl = np.unique(appl)
		for app in appl:
			for row in interim_result:
				if row[0] == app:
					b += int(row[1])
			byt.append(b)
		result = list(zip(appl,byt))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result)) <= top:
			print(f'Number of unique entries is less than this value!! Only {length} unique values are available !!\n')
			print(f'Running search for the Top {length} entries instead\n')
			top = int(len(result))
		result = result[:top]
	return result

# Quick Application Mode - Top Application Drill-down Source - Sort by Byte Count:

def QATBDrillSource(ApDrill,file,top):
	line_count = 0
	src, byt = [], []
	byte_count = []
	b = 0
	j = 0 
	n = 0
	result_table=PrettyTable(['#','Application','Source','Count'])
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if row[14] == ApDrill:
					src.append(row[7])
					byte_count.append(row[31])
					line_count += 1
		interim_result = list(zip(src,byte_count))
		print(f'{line_count} lines processed.')
		src = np.unique(src)
		print(f'Unqie entries = {int(len(src))}')
		for a in src:
			for row in interim_result:
				if row[0] == a:
					b += int(row[1])
			byt.append(b)
		result = list(zip(src,byt))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < top):
			top = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {top} instead')
		result = result[:top]
	return result

# Quick Application Mode - Top Application Drill-down Destination - Sort by Byte Count

def QATBDrillDestination(ApDrill,file,top):
	line_count = 0
	dst, byt = [], []
	byte_count = []
	b = 0
	j = 0 
	n = 0
	result_table=PrettyTable(['#','Application','Destination Address','Count'])
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if row[14] == ApDrill:
					dst.append(row[8])
					byte_count.append(row[31])
					line_count += 1
		interim_result = list(zip(dst,byte_count))
		print(f'{line_count} lines processed.')
		dst = np.unique(dst)
		for a in dst:
			for row in interim_result:
				if row[0] == a:
					b += int(row[1])
			byt.append(b)
		result = list(zip(dst,byt))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < top):
			top = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {top} instead')
		result = result[:top]
	print(f'\nTop Source Drll-down Done by Byte Count!!\n')
	return result

# Quick Application Mode - Top Applications - Sort By Session Count:

def QATSApplication(file, top):
	line_count = 0
	appl, byt = [], []
	count = []
	b = 0
	j = 0 
	n = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				appl.append(row[14])
				line_count += 1
		appl, count = np.unique(appl, return_counts=True)
		result = list(zip(appl,count))
		result.sort(key=lambda result: result[1], reverse=True)
		result_table = PrettyTable(['#','Application','Session Count'])
		if int(len(result) < top):
			top = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {re} instead')
		result = result[:top]
	print(f'\nTop Applications Done by Session Count!!\n')
	return result

#Quick Application-Mode - Drill-down Source - Sort by session Count:

def QATSDrillSource(ApDrill,file,top):
	line_count = 0
	src, byt = [], []
	count = []
	b = 0
	j = 0 
	n = 0
	result_table=PrettyTable(['#','Application','Source','Count'])
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if row[14] == ApDrill:
					src.append(row[7])
					line_count += 1
		src, count = np.unique(src, return_counts=True)
		print(f'Unqie entries = {int(len(src))}')
		result = list(zip(src,count))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < top):
			top = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {top} instead')
		result = result[:top]
	print(f'\nTop Source Drll-down Done by Session Count!!\n')
	return result

# Quick Application Mode - Drill-down Destination - Sort by Session Count

def QATSDrillDestination(ApDrill,file,top):
	line_count = 0
	dst, byt = [], []
	count = []
	b = 0
	j = 0 
	n = 0
	result_table=PrettyTable(['#','Application','Destination','Count'])
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				if row[14] == ApDrill:
					dst.append(row[8])
					line_count += 1
		dst, count = np.unique(dst, return_counts=True)
		result = list(zip(dst,count))
		result.sort(key=lambda result: result[1], reverse=True)
		if int(len(result) < top):
			top = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {top} instead')
		result = result[:top]
	print(f'\nTop Destination Drll-down Done by Session Count!!\n')
	return result


###############################################################################################

## QUICK-MODE MAIN functions

# Quick-Source mode:

def QuickSourceMode(f,t):
	resultSourceL1 = PrettyTable(['#','Source','Count'])
	resultSourceDestinationL2 = PrettyTable(['#','Source','Destination','Count'])
	resultSourceApplicationSessionL2 = PrettyTable(['#','Source', 'Application', 'Count'])
	resultSourceApplicationByteL2 = PrettyTable(['#','Source','Application','Bytes'])
	resultDestinationL1 = PrettyTable(['#','Source','Count'])
	resultDestinationSourceL2 = PrettyTable(['#', 'Destination', 'Source', 'Count'])
	print(f'Entering Quick Mode:\n')
	with open('results-source.txt', 'w') as outfile:
		print(f'\nTOP Source Mode:\n')
		outfile.write(f'\t\tQuick-Mode Output:\n\n')
		outfile.write(f'\n\nTop {t} Sources:\n\n')
		result = QSTSource(f,t)
		for i in range(int(len(result))):
			resultSourceL1.add_row([i+1, result[i][0], result[i][1]])
		outfile.write(f'{resultSourceL1}\n')
		outfile.write(f'\n------------------------------------------------------------------------\n')
		outfile.write(f'\t\tTop Destination  &  Application for Each of the Source:\n')
		print(f'\nTop Sources done!!\n')
		for i in range(int(len(result))):
			print(f'\nWriting Top Destinations for Source {result[i][0]}...\n')
			table1 = QSTDrilldestination(result[i][0], f,t)
			outfile.write(f'\nTop Destination for Source {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultSourceDestinationL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultSourceDestinationL2}\n')
			resultSourceDestinationL2.clear_rows()
			table1.clear()
			print(f'\nTop Application by Bytes/Session Per Source:\n')
			table1 = QSTDrillApplicationSession(result[i][0],f,t)
			outfile.write(f'\nTop Application by Session Count for Source {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultSourceApplicationSessionL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultSourceApplicationSessionL2}\n')
			resultSourceApplicationSessionL2.clear_rows()
			table1.clear()
			table1 = QSTDrillApplicationByte(result[i][0],f,t)
			outfile.write(f'\nTop Application by Byte Count for Source {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultSourceApplicationByteL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultSourceApplicationByteL2}\n')
			resultSourceApplicationByteL2.clear_rows()
			table1.clear()
			outfile.write(f'\n------------------------------------------------------------------------\n')
		result.clear()
		print(f'\nTop Destination  & Application for Each Source Completed!!\n')
	print(f'\n################################################################################\n')
	print(f'Please refer to ./results-source.txt for the Results of this run.\n')

## Quick-Destination Mode

def QuickDestMode(f,t):
	resultSourceL1 = PrettyTable(['#','Source','Count'])
	resultSourceDestinationL2 = PrettyTable(['#','Source','Destination','Count'])
	resultDestinationL1 = PrettyTable(['#','Destination','Count'])
	resultDestinationSourceL2 = PrettyTable(['#', 'Destination', 'Source', 'Count'])
	resultDestinationApplicationSessionL2 = PrettyTable(['#','Destination', 'Application', 'Count'])
	resultDestinationApplicationByteL2 = PrettyTable(['#','Destination','Application','Bytes'])
	print(f'Entering Quick Mode:\n')
	with open('results-destination.txt', 'w') as outfile:
		outfile.write(f'\t\tQuick-Mode Output:\n\n')
		print(f'\nTop Destination Mode:\n')
		outfile.write(f'\n\nTop {t} Destinations:\n\n')
		result = QDTDestination(f,t)
		for i in range(int(len(result))):
			resultDestinationL1.add_row([i+1, result[i][0], result[i][1]])
		outfile.write(f'{resultDestinationL1}\n')
		outfile.write(f'\n------------------------------------------------------------------------\n')
		outfile.write(f'\t\tTop Source for Each of the Destination:\n')
		print(f'\nTop Destinations done!!\n')
		for i in range(t):
			print(f'Writing Top Sources for Destination {result[i][0]}...\n')
			table1 = QDTDrillSource(result[i][0], f,t)
			outfile.write(f'\nTop Sources for Destination {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultDestinationSourceL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultDestinationSourceL2}\n')
			resultDestinationSourceL2.clear_rows()
			table1.clear()
			print(f'\nTop Application by Bytes/Session Per Destination:\n')
			table1 = QSTDrillApplicationSession(result[i][0],f,t)
			outfile.write(f'\nTop Application by Session Count for Source {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultDestinationApplicationSessionL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultDestinationApplicationSessionL2}\n')
			resultDestinationApplicationSessionL2.clear_rows()
			table1.clear()
			table1 = QSTDrillApplicationByte(result[i][0],f,t)
			outfile.write(f'\nTop Application by Byte Count for Source {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultDestinationApplicationByteL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultDestinationApplicationByteL2}\n')
			resultDestinationApplicationByteL2.clear_rows()
			table1.clear()
			outfile.write(f'\n------------------------------------------------------------------------\n')
		result.clear()
		print(f'\nTop Destination  & Application for Each Destination Completed!!\n')
	print(f'\n################################################################################\n')
	print(f'Please refer to ./results-destination.txt for the Results of this run.\n')

## Quick-Application Mode:

def QuickApplMode(f,t):
	resultApplicationByteL1 = PrettyTable(['#','Application','Byte Count'])
	resultApplicationSessionL1 = PrettyTable(['#','Application','Session Count'])
	resultApplicationByteSourceL2 = PrettyTable(['#', 'Application', 'Source', 'Byte Count'])
	resultApplicationSessionSourceL2 = PrettyTable(['#', 'Application', 'Source', 'Session Count'])
	resultApplicationByteDestinationL2 = PrettyTable(['#', 'Application', 'Destination', 'Byte Count'])
	resultApplicationSessionDestinationL2 = PrettyTable(['#','Application','Destination','Sesion Count'])
	print(f'Entering Quick Mode:\n')
	with open('results-application.txt', 'w') as outfile:
		outfile.write(f'\t\tQuick-Mode Output:\n\n')
		print(f'\nTop Application (Byte Count) Mode:\n')
		outfile.write(f'\n\nTop {t} Applications (Byte Count):\n\n')
		result = QATBApplication(f,t)
		for i in range(int(len(result))):
			resultApplicationByteL1.add_row([i+1, result[i][0], result[i][1]])
		outfile.write(f'{resultApplicationByteL1}\n')
		print(f'{resultApplicationByteL1}')
		outfile.write(f'\n------------------------------------------------------------------------\n')
		outfile.write(f'\t\tTop Source/Destination for Each of the Application (Byte Count):\n')
		for i in range(t):
			print(f'Writing Top Sources for Application {result[i][0]}...\n')
			table1 = QATBDrillSource(result[i][0], f,t)
			outfile.write(f'\nTop Sources for Application {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultApplicationByteSourceL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultApplicationByteSourceL2}\n')
			resultApplicationByteSourceL2.clear_rows()
			table1.clear()
			print(f'\nWriting Top Destinations for a given Application {result[i][0]}\n')
			table1 = QATBDrillDestination(result[i][0],f,t)
			outfile.write(f'\n Top Destination for a given application {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultApplicationByteDestinationL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultApplicationByteDestinationL2}\n')
			resultApplicationByteDestinationL2.clear_rows()
			table1.clear()
		print(f'\nTop Applications by Byte Count done!!\n')
		result.clear()
		print(f'\nTop Applications by Session Count:\n')
		outfile.write(f'\n------------------------------------------------------------------------\n')
		outfile.write(f'\n------------------------------------------------------------------------\n')
		outfile.write(f'\n\nTop {t} Applications (Session Count):\n\n')
		result = QATSApplication(f,t)
		for i in range(int(len(result))):
			resultApplicationSessionL1.add_row([i+1, result[i][0], result[i][1]])
		outfile.write(f'{resultApplicationSessionL1}\n')
		print(f'{resultApplicationSessionL1}')
		outfile.write(f'\n------------------------------------------------------------------------\n')
		outfile.write(f'\t\tTop Source/Destination for Each of the Application (Session Count):\n')
		for i in range(t):
			print(f'Writing Top Sources for Application {result[i][0]}...\n')
			table1 = QATSDrillSource(result[i][0], f,t)
			outfile.write(f'\nTop Sources for Application {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultApplicationSessionSourceL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultApplicationSessionSourceL2}\n')
			resultApplicationSessionSourceL2.clear_rows()
			table1.clear()
			print(f'\nWriting Top Destinations for a given Application {result[i][0]}\n')
			table1 = QATSDrillDestination(result[i][0],f,t)
			outfile.write(f'\n Top Destination for a given application {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultApplicationSessionDestinationL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultApplicationSessionDestinationL2}\n')
			resultApplicationSessionDestinationL2.clear_rows()
			table1.clear()
		print(f'\nTop Applications by Byte Count done!!\n')
		table1.clear()
		outfile.write(f'\n------------------------------------------------------------------------\n')
		result.clear()
		print(f'\nTop Sources and Destination for Each Application Completed!!\n')
	print(f'\n################################################################################\n')
	print(f'Please refer to ./results-application.txt for the Results of this run.\n')

# QICK MODE Definitions are done!!

###############################################################################################################
###############################################################################################################


# Main Definition:

def main():
	try:
		parser = argparse.ArgumentParser(description='This Script is desgined to parse through Detailed CSV Traffic log files and print usable informtion for DP CPU over-utilization', add_help=True)
		group_root = parser.add_mutually_exclusive_group(required=True)
		group_root.add_argument('-qs','--quicksrc', help="Use this mode to directly print out the information centered on Source Addresses (Client-Mode) into a text file as described on <DOC>. Usage: TLP [--quicksource | -qs ] [--top| -t] TOP <filename.csv>", action='store_true')
		group_root.add_argument('-qd','--quickdst', help='Use this mode to directly print out information centered on Destination Addresses (Serve-Mode) into a text file as described on <Doc>. Usage: TLP [--quickdestination | -qd] [--top | -t] TOP <filename.csv>', action="store_true")
		group_root.add_argument('-qa','--quickapp', help='Use this mode to directly print out information centered on Application Usage into a text file on as described on <Doc>. Usage: TLP [--quickapplication | -qa] [--top | -t] TOP <filename.csv>', action="store_true")
		group_root.add_argument('-w','--wizard', help="Interactive Mode desgined to go through a series of steps. Usage: TLP [--interactive | -i] <filename.csv>", action='store_true')
		group_root.add_argument('-s','--source', help="Source Mode, designed to print out only the <TOP> Sources and their Session Count from the logs. If no TOP argument is provided using the flag [-t | --top], then the script will default to TOP 10 Entries. Usage: TLP [--source | -s] [--top|-t] <IP-Address> <filename.csv>", action='store_true')
		group_root.add_argument('-ds','--drillsrc', help="Drill-Down Source Mode designed for quick drill-down data based on Source IP address. With this, you can automatically have the script dump the TOP destinations and the TOP application usage for the Source Address. Usage: TLP -ds SOURCE [-t TOP] <filename.csv>", action='store')
		group_root.add_argument('-d','--destination', help="Destination Mode, desgined to print out only the the <TOP> Destination from the Traffic Logs. If no TOP argument is provided using the flag [-t | --top], then the script will default to TOP 10 Entries. Usage: TLP [--destination | -s] [--top|-t] <IP-Address> <filename.csv>", action='store_true') 
		group_root.add_argument('-dd','--drilldst', help="Drill-Down Destination Mode designed for quick drill-down data based on Destination IP address. With this, you can automatically have the script dump the TOP destinations and application for each of the source based on the Destination Address. Usage: TLP -dd DESTINATION [-t TOP] <filename.csv>", action='store')
		parser.add_argument('-t','--top', help="Sets the TOP entries required", action='store')
		parser.add_argument('filename', metavar='File', help='XML file name for parsing', action='store')
		args = parser.parse_args()
		f = format(args.filename)
		if(format(args.filename) == "None"):
			print (f'No File Name given!!')
			exit()
		if (format(args.top) == "None"):
			print (f'No # for TOP entries given, defaulting to TOP 10 entries')
			t = 10
		else:
			t = int(format(args.top))
		if (format(args.quicksrc) == 'True'):
			QuickSourceMode(f,t)
		if (format(args.quickdst) == 'True'):
			QuickDestMode(f,t)
		if (format(args.quickapp) == 'True'):
			QuickApplMode(f,t)
		if (format(args.wizard) == 'True'):
			print(f'\n\n\nSo what do you want to do today?\n\n\n')
			while 1:
				print(f'\n1. Top Source mode (Client Mode)?')
				print(f'\n2. Top Destination mode (Server Mode)?')
				print(f'\n3. Identify the top seessions based on bytes (Top Applications Mode)?')
				print(f'\nOnly enter the # between 1 & 3, please, its a work in progress, Ill you UAT this thing to the worlds end later, I promise :)\n')
				opt = int(input('Enter the option, use 0 for exit: '))
				if opt == 0:
					break
				elif opt == 1:
					print(f'\nTop Source Mode\n')
					result_table = STSource(f,t)
					print(f'The top {t} source are:\n')
					print(f'{result_table}')
					print(f'\nFile Processing Done!!\n')
					print(f'\n ##################################################################### \n')
					print(f'\nTop Source Drill-down Mode:\n')
					drill_IP = str(input('\nEnter the Source to Drill down on: '))
					while 1:
						print(f'\nTop Source Drill-down Options:\n')
						print(f'\n1. Top Destinations for {drill_IP}?\n')
						print(f'\n2. Top Applications accessed by {drill_IP}?\n')
						print(f'\n3. Go back to the previous menu. \n')
						sC = int(input('\nEnter the option # from above: '))
						if sC == 1:
							result_table = STDrilldestination(drill_IP,f,t)
							print(f'{result_table}')
							print(f'\nTop Destination drill-down done for {drill_IP}.\n')
							l = 0 
						elif sC == 2:
							while 1:
								print(f'\nTop Applications Mode\n')
								print(f'\nChoose from the following options on the Sort order:\n')
								print(f'1. Top Applications - Sorted by bytes\n')
								print(f'2. Top Applications - Sorted by Session Count\n')
								print(f'3. Go back to the previous menu\n')
								DrOpt = int(input('Enter the option # from above: ') )
								if DrOpt == 1:
									print(f'\nTop Applications for source {drill_IP} by Byte Count')
									result_table = STDrillApplication(f,drill_IP,t,'b')
									print(f'{result_table}')
								elif DrOpt == 2:
									print(f'\nTop Applications for source {drill_IP} by Session Count')
									result_table = STDrillApplication(f,drill_IP,t,'s')
									print(f'{result_table}')
								elif DrOpt == 3:
									break
								else:
									print(f'Wrong Input!!')
						elif sC == 3:
							l = 0
							break
						else:
							print(f'\nFunny Guy, eh? Please select the right option :)\n')
				elif opt == 2:
					print(f'\nServer-Mode\n')
					result_table = DTDestination(f,t)
					print(f'{result_table}')
					print(f'\nFile Processing Done!!\n')
					print(f'\n ##################################################################### \n')
					print(f'\nTop Destination Drill-down Mode:\n')
					drill_IP = str(input('\nEnter the Destination to Drill down on: '))
					while 1:
						print(f'\nTop Destination Drill-down Options:\n')
						print(f'\n1. Top Sources for {drill_IP}?\n')
						print(f'\n2. Top Applications accessed on {drill_IP}?\n')
						print(f'\n3. Go back to the previous menu. \n')
						sC = int(input('\nEnter the option # from above: '))
						if sC == 1:
							result_table = DTDrillsource(f,drill_IP,t)
							print(f'{result_table}')
							print(f'\nTop Sources drill-down done for {drill_IP}.\n')
							l = 0 
						elif sC == 2:
							while 1:
								print(f'\nTop Applications Mode\n')
								print(f'\nChoose from the following options on the Sort order:\n')
								print(f'1. Top Applications - Sorted by bytes\n')
								print(f'2. Top Applications - Sorted by Session Count\n')
								print(f'3. Go back to the previous menu\n')
								DrOpt = int(input('Enter the option # from above: ') )
								if DrOpt == 1:
									print(f'\nTop Applications for source {drill_IP} by Byte Count')
									result_table = DTDrillApplication(f,drill_IP,t,'b')
									print(f'{result_table}')
								elif DrOpt == 2:
									print(f'\nTop Applications for source {drill_IP} by Session Count')
									result_table = DTDrillApplication(f,drill_IP,t,'s')
									print(f'{result_table}')
								elif DrOpt == 3:
									break
								else:
									print(f'Wrong Input!!')
						elif sC == 3:
							l = 0
							break
						else:
							print(f'\nFunny Guy, eh? Please select the right option :)\n')
					print(f'\nServer-Mode Done.\n')
				elif opt == 3:
					while 1:
						print(f'\nTop Application-mode\n')
						print(f'\nChoose from the following options on the Sort order:\n')
						print(f'1. Top Applications - Sorted by bytes\n')
						print(f'2. Top Applications - Sorted by Session Count\n')
						print(f'3. Go back to the previous menu\n')
						ApOpt = int(input('Enter the option # from above: '))
						if ApOpt == 1:
							result_table = ATBApplication(f,t)
							print(f'{result_table}')
							print(f'Top Applications by Byte Count Done.')
							ApDrill = str(input('Enter the Application name that you would like to drill down on: '))
							while 1:
								print(f'\nTop Application (bytes) Drill-Down Menu\n')
								print(f'\nChoose from the following options on the Drill-down\n')
								print(f'\n1. Top Sources using the Application?')
								print(f'\n2. Top Destination where the application was accessed from?')
								print(f'\n3. Go Back to the previous menu')
								ApDrOpt = int(input('Enter the option # from above: '))
								if ApDrOpt == 1:
									result_table = ATBDrillSource(f,ApDrill,t)
									print(f'{result_table}')
								elif ApDrOpt == 2:
									result_table = ATBDrillDestination(f,ApDrill,t)
									print(f'{result_table}')
								elif ApDrOpt == 3:
									break
								else:
									print(f'We have been through this!! There is nothing to see here!!')
						elif ApOpt == 2:
							result_table = ATSApplication(f,t)
							print(f'{result_table}')
							ApDrill = str(input('Enter the Application name that you would like to drill down on: '))
							while 1:
								print(f'\nTop Application (Sessions) Drill-Down Menu\n')
								print(f'\nChoose from the following options on the Drill-down\n')
								print(f'\n1. Top Sources using the Application?')
								print(f'\n2. Top Destination where the application was accessed from?')
								print(f'\n3. Go Back to the previous menu')
								ApDrOpt = int(input('Enter the option # from above: '))
								if ApDrOpt == 1:
									result_table = ATSDrillSource(f,ApDrill,t)
									print(f'{result_table}')
								elif ApDrOpt == 2:
									result_table = ATSDrillDestination(f,ApDrill,t)
									print(f'{result_table}')
								elif ApDrOpt == 3:
									break
								else:
									print(f'Still No Dice!!')
						elif ApOpt == 3:
							break
						else:
							print(f'Nope! Wrong Input, Bro!!')
				else:
					print(f'Really?? You chose a different number despite me telling you not to? Come on, youre better than this :)')		
			print(f'Run Completed!!')
		if(format(args.source) == 'True'):
			print(f'\nTop Source Mode:\n')
			ip_list = STSource(f,t)
			print(f'\nThe Top {t} Source from the file {f} are:\n')
			print(f'\nFile Processing Done!!\n')
			print(f'{ip_list}')
			print(f'\n ##################################################################### \n')
		if(format(args.destination) == 'True'):
			print(f'\nTop Destination Mode:\n')
			ip_list = DTDestination(f,t)
			print(f'\nThe Top {t} Destinations from the file {f} are:\n')
			print(f'\nFile Processing Done!!\n')
			print(f'{ip_list}')
			print(f'\n ##################################################################### \n')
		if(format(args.drillsrc) != 'None'):
			drillIP = format(agrs.drillsrc)
			print(f'\nDrill-Down Source Mode:\n')
			result_table_dest = STDrilldestination(drillIP,f,t)
			print(f'\nTop Destinations for the Source {drillIP}:\n')
			print(f'{result_table_dest}\n')
			result_table_appB = STDrilldestination(f,drillIP,t,'b')
			result_table_appS = STDrillApplication(f,drillIP,t,'s')
			print(f'\nTop Applications (byte Count) for Source {drillIP}\n')
			print(f'{result_table_appB}\n')
			print(f'\nTop Applications (Session Count) for Source {drillIP}\n')
			print(f'{result_table_appS}\n')
			print(f'\nFile Processing Done!!\n')
			print(f'\n ##################################################################### \n')
		if(format(args.drilldst) != 'None'):
			drillIP = format(agrs.drillsrc)
			print(f'\nDrill-Down Destination Mode:\n')
			result_table_dest = DTDrillsource(f,drillIP,t)
			print(f'\nTop Sources for the Destination {drillIP}:\n')
			print(f'{result_table_src}\n')
			result_table_appB = DTDrilldestination(f,drillIP,t,'b')
			result_table_appS = DTDrillApplication(f,drillIP,t,'s')
			print(f'\nTop Applications (byte Count) for Destination {drillIP}\n')
			print(f'{result_table_appB}\n')
			print(f'\nTop Applications (Session Count) for Destination {drillIP}\n')
			print(f'{result_table_appS}\n')
			print(f'\nFile Processing Done!!\n')
			print(f'\n ##################################################################### \n')
	except KeyboardInterrupt:
		print(f'Keyboard Interrupt Detected! Thank You!.')


main()
