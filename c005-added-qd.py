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

#Function Definition:

def sort(result):
	i = len(result)
	n = 0
	ip = ''
	index = 0
	
	#Check for the largest value of count

	for j in range(i):
		if n < int(result[j][1]):
			n = int(result[j][1])
			ip = str(result[j][0])
			index = j
	return ip, n, index

def DTDestination(file):
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
		length = int(len(result))
		print(f'{length} unique entries are available')
	
		#Identify TOP Sources
	
		rows = int(input('Enter the number of top entries required: '))
		print(f'#.  IP address , Count')
		if length <= rows:
			print(f'Number of unique entries is less than this value!! Only {length} unique values are available !!')
			print(f'Running search for the Top {length} entries instead')
			for x in range(length):
				final_ip, final_count, y = sort(result)
				print(f'{x+1}. {final_ip} , {final_count}')
				ip_list.append(final_ip)
				result.pop(y)
		else:
			for x in range(rows):
				final_ip, final_count, y = sort(result)
				print(f'{x+1}. {final_ip} , {final_count}')
				ip_list.append(final_ip)
				result.pop(y)
	return ip_list

def DTsource(ip_list,file):	
	src1 = []
	dest1 = [[],[]]
	x = 0
	lc = len(ip_list)
	#print(f'{ip_list}, {len(ip_list)}')
	for i in range(lc):
		with open(file,  mode='r') as csv_file:
			csv_reader = csv.reader(csv_file, delimiter=',')
			for row in csv_reader:
				if str(ip_list[i])==row[8]:
					src1.append(row[7])
			d1, count1 = np.unique(src1, return_counts=True)
			dest1 = list(zip(d1, count1))
			print(f'\nIdentifying the TOP 10 sources that accessed destination {ip_list[i]}\n')
			print(f'\n#. IP Address , Count\n' )
			l = int(len(dest1))
			if l > 10:
				l = 10
			for x in range(l):
				final_ip, final_count, y = sort(dest1)
				print(f'{x+1}. {final_ip} , {final_count}')
				if int(y) >= 0:
					dest1.pop(y)
			print(f'Sources done for {ip_list[i]}')
		dest1 = [[],[]]
		src1 = []

def DTDrillsource(drill_IP,file,top):	
	dst1 = []
	src1 = [[],[]]
	x = 0
	l = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if str(drill_IP)==row[8]:
				dst1.append(row[7])
		s1, count1 = np.unique(dst1, return_counts=True)
		src1 = list(zip(s1, count1))
		if int(len(src1)) < top:
			top = int(len(src1))
			print(f'Not enough unique entries!! Seaching for {top} entries instead.')
		print(f'\nIdentifying the Top {top} Sources for Destination {drill_IP}\n')
		print(f'#. IP Address , Count' )
		for x in range(top):
			final_ip, final_count, y = sort(dst1)
			print(f'{x+1}. {final_ip} , {final_count}')
			if int(y) >= 0:
				dest1.pop(y)
	print(f'Sources done for {drill_IP}')
	dest1 = [[],[]]
	src1 = []

def DTDrillApplication(file, dest, opt):
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
		if opt == 'b':
			interim_result = list(zip(appl,byte_count))
			appl = np.unique(appl)
			for app in appl:
				for row in interim_result:
					if row[0] == app:
						b += int(row[1])
				byt.append(b)
			result = list(zip(appl,byt))
			req = int(input('Enter the number of Top Entries required: '))
			if int(len(result) < req):
				print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
				req = int(len(result))
			print(f'#. Application, Total Bytes ')
			for i in range(req):
				for j in range(int(len(result))):
					if n < int(result[j][1]):
						n = result[j][1]
						ap = result[j][0]
						index = j
				result.pop(index)
				print(f'{i+1}. {ap},  {n}')
				j = 0
				n = 0
			print(f'\nTop Applications Done by Byte Count!!\n')
		elif opt == 's':
			app, count = np.unique(appl, return_counts=True)
			result = list(zip(app,count))
			req = int(input('Enter the number of Top Entries required: '))
			if int(len(result) < req):
				print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
				req = int(len(result))
			print(f'#. Application, Total Count ')
			for i in range(req):
				for j in range(int(len(result))):
					if n < int(result[j][1]):
						n = result[j][1]
						ap = result[j][0]
						index = j
				result.pop(index)
				print(f'{i+1}. {ap},  {n}')
				j = 0
				n = 0
			print(f'\nTop Applications Done by Session Count!!\n')
	print(f'Module Done!!')


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

def STdestination(ip_list,file):	
	src1 = []
	dest1 = [[],[]]
	x = 0
	lc = len(ip_list)
	#print(f'{ip_list}, {len(ip_list)}')
	for i in range(lc):
		with open(file,  mode='r') as csv_file:
			csv_reader = csv.reader(csv_file, delimiter=',')
			for row in csv_reader:
				if str(ip_list[i])==row[7]:
					src1.append(row[8])
			d1, count1 = np.unique(src1, return_counts=True)
			dest1 = list(zip(d1, count1))
			print(f'\nIdentifying the TOP 10 destinations of source {ip_list[i]}\n')
			print(f'#. IP Address , Count' )
			l = int(len(dest1))
			if l > 10:
				l = 10
			for x in range(l):
				final_ip, final_count, y = sort(dest1)
				print(f'{x+1}. {final_ip} , {final_count}')
				if int(y) >= 0:
					dest1.pop(y)
			print(f'Sources done for {ip_list[i]}')
		dest1 = [[],[]]
		src1 = []

def STDrilldestination(drill_IP,file,top):	
	src1 = []
	dest1 = [[],[]]
	x = 0
	l = 0
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
		print(f'#. IP Address , Count' )
		for x in range(top):
			final_ip, final_count, y = sort(dest1)
			print(f'{x+1}. {final_ip} , {final_count}')
			if int(y) >= 0:
				dest1.pop(y)
	print(f'Destinations done for {drill_IP}')
	dest1 = [[],[]]
	src1 = []

def STDrillApplication(file, source, opt):
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
			interim_result = list(zip(appl,byte_count))
			appl = np.unique(appl)
			for app in appl:
				for row in interim_result:
					if row[0] == app:
						b += int(row[1])
				byt.append(b)
			result = list(zip(appl,byt))
			req = int(input('Enter the number of Top Entries required: '))
			if int(len(result) < req):
				print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
				req = int(len(result))
			print(f'#. Application, Total Bytes ')
			for i in range(req):
				for j in range(int(len(result))):
					if n < int(result[j][1]):
						n = result[j][1]
						ap = result[j][0]
						index = j
				result.pop(index)
				print(f'{i+1}. {ap},  {n}')
				j = 0
				n = 0
			print(f'\nTop Applications Done by Byte Count!!\n')
		elif opt == 's':
			app, count = np.unique(appl, return_counts=True)
			result = list(zip(app,count))
			req = int(input('Enter the number of Top Entries required: '))
			if int(len(result) < req):
				print(f'Not Enough Entries!! Displaying the TOP {int(len(result))} instead')
				req = int(len(result))
			print(f'#. Application, Total Count ')
			for i in range(req):
				for j in range(int(len(result))):
					if n < int(result[j][1]):
						n = result[j][1]
						ap = result[j][0]
						index = j
				result.pop(index)
				print(f'{i+1}. {ap},  {n}')
				j = 0
				n = 0
			print(f'\nTop Applications Done by Session Count!!\n')
	print(f'Module Done!!')

def ATBApplication(file):
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
		re = int(input('Enter the number of Top Entries required: '))
		if int(len(result) < re):
			re = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {re} instead')
		print(f'#. Application, Total Bytes ')
		for i in range(re):
			for j in range(int(len(result))):
				if n < int(result[j][1]):
					n = result[j][1]
					ap = result[j][0]
					index = j
			result.pop(index)
			print(f'{i+1}. {ap},  {n}')
			j = 0
			n = 0
	print(f'\nTop Applications Done by Byte Count!!\n')

def ATBDrillSource(file,ApDrill):
	line_count = 0
	src, byt = [], []
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
				if row[14] == ApDrill:
					src.append(row[7])
					byte_count.append(row[31])
					line_count += 1
		interim_result = list(zip(src,byte_count))
		print(f'length of result = {int(len(interim_result))}')
		print(f'{line_count} lines processed.')
		src = np.unique(src)
		print(f'Unqie entries = {int(len(src))}')
		for a in src:
			for row in interim_result:
				if row[0] == a:
					b += int(row[1])
			byt.append(b)
		result = list(zip(src,byt))
		re = int(input('Enter the number of Top Entries required: '))
		if int(len(result) < re):
			re = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {re} instead')
		print(f'#. Source IP , Total Bytes ')
		for i in range(re):
			for j in range(int(len(result))):
				if n < int(result[j][1]):
					n = result[j][1]
					ap = result[j][0]
					index = j
			result.pop(index)
			print(f'{i+1}. {ap},  {n}')
			j = 0
			n = 0
	print(f'\nTop Source Drll-down Done by Byte Count!!\n')

def ATBDrillDestination(file,ApDrill):
	line_count = 0
	dst, byt = [], []
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
				if row[14] == ApDrill:
					dst.append(row[8])
					byte_count.append(row[31])
					line_count += 1
		interim_result = list(zip(dst,byte_count))
		print(f'length of result = {int(len(interim_result))}')
		print(f'{line_count} lines processed.')
		dst = np.unique(dst)
		print(f'Unqie entries = {int(len(dst))}')
		for a in dst:
			for row in interim_result:
				if row[0] == a:
					b += int(row[1])
			byt.append(b)
		result = list(zip(dst,byt))
		re = int(input('Enter the number of Top Entries required: '))
		if int(len(result) < re):
			re = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {re} instead')
		print(f'\nTop Destinations for Application {ApDrill}')
		print(f'#. Destination IP , Total Bytes ')
		for i in range(re):
			for j in range(int(len(result))):
				if n < int(result[j][1]):
					n = result[j][1]
					ap = result[j][0]
					index = j
			result.pop(index)
			print(f'{i+1}. {ap},  {n}')
			j = 0
			n = 0
	print(f'\nTop Source Drll-down Done by Byte Count!!\n')

def ATSApplication(file):
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
		interim_result = list(zip(appl,byte_count))
		appl, count = np.unique(appl, return_counts=True)
		result = list(zip(appl,count))
		re = int(input('Enter the number of Top Entries required: '))
		if int(len(result) < re):
			re = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {re} instead')
		print(f'#. Application, Total Bytes ')
		for i in range(re):
			for j in range(int(len(result))):
				if n < int(result[j][1]):
					n = result[j][1]
					ap = result[j][0]
					index = j
			result.pop(index)
			print(f'{i+1}. {ap},  {n}')
			j = 0
			n = 0
	print(f'\nTop Applications Done by Session Count!!\n')

def ATSDrillSource(file,ApDrill):
	line_count = 0
	src, byt = [], []
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
				if row[14] == ApDrill:
					src.append(row[7])
					line_count += 1
		src, count = np.unique(src, return_counts=True)
		print(f'Unqie entries = {int(len(src))}')
		result = list(zip(src,count))
		re = int(input('Enter the number of Top Entries required: '))
		if int(len(result) < re):
			re = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {re} instead')
		print(f'#. Source IP , Total Bytes ')
		for i in range(re):
			for j in range(int(len(result))):
				if n < int(result[j][1]):
					n = result[j][1]
					ap = result[j][0]
					index = j
			result.pop(index)
			print(f'{i+1}. {ap},  {n}')
			j = 0
			n = 0
	print(f'\nTop Source Drll-down Done by Session Count!!\n')

def ATSDrillDestination(file,ApDrill):
	line_count = 0
	dst, byt = [], []
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
				if row[14] == ApDrill:
					dst.append(row[8])
					line_count += 1
		dst, count = np.unique(dst, return_counts=True)
		result = list(zip(dst,count))
		re = int(input('Enter the number of Top Entries required: '))
		if int(len(result) < re):
			re = int(len(result))
			print(f'Not Enough Entries!! Displaying the TOP {re} instead')
		print(f'\nTop Destinations for Application {ApDrill}')
		print(f'#. Destination IP , Total Bytes ')
		for i in range(re):
			for j in range(int(len(result))):
				if n < int(result[j][1]):
					n = result[j][1]
					ap = result[j][0]
					index = j
			result.pop(index)
			print(f'{i+1}. {ap},  {n}')
			j = 0
			n = 0
	print(f'\nTop Source Drll-down Done by Session Count!!\n')



def Tsession(file):
	line_count = 0
	with open(file,  mode='r') as csv_file:
		csv_reader = csv.reader(csv_file, delimiter=',')
		for row in csv_reader:
			if line_count == 0:
				line_count += 1
			else:
				ip_src.append(row[7])
				byte_count.append(row[31])
				ip_dst.append(row[8])
				appl.append(row[14])
				line_count += 1	
		print(f'Processed {line_count} lines.')
		result = list(zip(ip_src, ip_dst, appl, byte_count))
	return result

def TSessionSort(result):
	i = len(result)
	n = 0
	index = 0
	#Check for the largest value of count
	for j in range(i):
		if n < int(result[j][3]):
			n = int(result[j][3])
			ip = str(result[j][0])
			dst = str(result[j][1])
			app = str(result[j][2])
			index = j
	return ip, dst, n, app, index

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
		for i in range(t):
			print(f'\nWriting Top Destinations for Source {result[i][0]}...\n')
			table1 = QSTDrilldestination(result[i][0], f,t)
			outfile.write(f'\nTop Destination for Source {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultSourceDestinationL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultSourceDestinationL2}\n')
			resultSourceDestinationL2.clear_rows()
			table1.clear()
			print(f'\nTop Application by Bytes/Session Per Source:\n')
			table1 = QDTDrillApplicationSession(result[i][0],f,t)
			outfile.write(f'\nTop Application by Session Count for Source {result[i][0]}\n')
			for j in range(int(len(table1))):
				resultSourceApplicationSessionL2.add_row([j+1, result[i][0], table1[j][0], table1[j][1]])
			outfile.write(f'{resultSourceApplicationSessionL2}\n')
			resultSourceApplicationSessionL2.clear_rows()
			table1.clear()
			table1 = QDTDrillApplicationByte(result[i][0],f,t)
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

def QuickDestMode(f,t):
	resultSourceL1 = PrettyTable(['#','Source','Count'])
	resultSourceDestinationL2 = PrettyTable(['#','Source','Destination','Count'])
	resultDestinationL1 = PrettyTable(['#','Source','Count'])
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
#Main Definition

def main():
	try:
		parser = argparse.ArgumentParser(description='This Script is desgined to parse through Detailed CSV Traffic log files and print usable informtion for DP CPU over-utilization', add_help=True)
		group_root = parser.add_mutually_exclusive_group(required=True)
		group_root.add_argument('-qs','--quicksrc', help="Use this mode to directly print out the information centered on Source Addresses (Client-Mode) into a text file as described on <DOC>. Usage: TLP [--quicksource | -qs ] [--top| -t] TOP <filename.csv>", action='store_true')
		group_root.add_argument('-qd','--quickdst', help='Use this mode to directly print out information centered on Destination Addresses (Serve-Mode) into a text file as described on <Doc>. Usage: TLP [--quickdestination | -qd] [--top | -t] TOP <filename.csv>', action="store_true")
		group_root.add_argument('-qa','--quickapp', help='Use this mode to directly print out information centered on Application Usage into a text file on as described on <Doc>. Usage: TLP [--quickapplication | -qa] [--top | -t] TOP <filename.csv>', action="store_true")
		group_root.add_argument('-w','--wizard', help="Interactive Mode desgined to go through a series of steps. Usage: TLP [--interactive | -i] <filename.csv>", action='store_true')
		group_root.add_argument('-s','--source', help="Source Mode, desgined to start by automatically listing the <TOP> sources from the Traffic Logs. You can use this to continue drilling down using TOP Destinations or Applications. If no TOP argument is provided using the flag [-t | --top], then the script will default to TOP 10 Entries. Usage: TLP [--source | -s] [--top|-t] <IP-Address> <filename.csv>", action='store_true')
		group_root.add_argument('-ds','--drillsrc', help="Drill-Down Mode designed for quick drill-down data based on Source IP address. With this, you can automatically have the script dump the TOP destinations and application for each of the destination based on the Source Address. Usage: TLP -ds SOURCE [-t TOP] <filename.csv>", action='store')
		group_root.add_argument('-d','--destination', help="Destination Mode, desgined to start by automatically listing the <TOP> Destination from the Traffic Logs. You can use this to continue drilling down using TOP Sources or Applications. If no TOP argument is provided using the flag [-t | --top], then the script will default to TOP 10 Entries. Usage: TLP [--destination | -s] [--top|-t] <IP-Address> <filename.csv>", action='store_true') 
		group_root.add_argument('-dd','--drilldst', help="Drill-Down Mode designed for quick drill-down data based on Destination IP address. With this, you can automatically have the script dump the TOP destinations and application for each of the source based on the Destination Address. Usage: TLP -dd DESTINATION [-t TOP] <filename.csv>", action='store')
		parser.add_argument('-t','--top', help="Sets the TOP entries required", action='store')
		parser.add_argument('filename', metavar='File', help='XML file name for parsing', action='store')
		args = parser.parse_args()
		if(format(args.filename) == "None"):
			print (f'No File Name given!!')
			exit()
		if (format(args.top) == "None"):
			print (f'No # for TOP entries given, defaulting to TOP 10 entries')
			t = 10
		else:
			t = int(format(args.top))
		f = format(args.filename)
		if (format(args.quicksrc) == 'True'):
			QuickSourceMode(f,t)
		if (format(args.quickdst) == 'True'):
			QuickDestMode(f,t)
		if (format(args.source) == "None"):
			print (f'No Source Given')
		print(f'{args.source}')
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
							l = int(input('Enter the number of Top destinations required: '))
							STDrilldestination(drill_IP,f,l)
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
									STDrillApplication(f,drill_IP,'b')
								elif DrOpt == 2:
									print(f'\nTop Applications for source {drill_IP} by Session Count')
									STDrillApplication(f,drill_IP,'s')
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
					ip_list = DTDestination(f)
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
							l = int(input('Enter the number of Top sources required: '))
							DTDrillsource(drill_IP,f,l)
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
									DTDrillApplication(f,drill_IP,'b')
								elif DrOpt == 2:
									print(f'\nTop Applications for source {drill_IP} by Session Count')
									DTDrillApplication(f,drill_IP,'s')
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
					result = Tsession(f)
					l = int(input('Enter the number of Top Session by bytes: '))
					if l == 0:
						print(f'Incorrect value')
					print(f'\n #.  IP Source , IP Destination, application, bytes')
					for i in range(l):
						ip, src, byt, app, y = TSessionSort(result)
						print(f'{i+1}. {ip}, {src}, {app} , {byt}')
						if int(y) >= 0:
							result.pop(y)
				elif opt == 4:
					while 1:
						print(f'\nTop Application-mode\n')
						print(f'\nChoose from the following options on the Sort order:\n')
						print(f'1. Top Applications - Sorted by bytes\n')
						print(f'2. Top Applications - Sorted by Session Count\n')
						print(f'3. Go back to the previous menu\n')
						ApOpt = int(input('Enter the option # from above: '))
						if ApOpt == 1:
							ATBApplication(f)
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
									ATBDrillSource(f,ApDrill)
								elif ApDrOpt == 2:
									ATBDrillDestination(f,ApDrill)
								elif ApDrOpt == 3:
									break
								else:
									print(f'We have been through this!! There is nothing to see here!!')
						elif ApOpt == 2:
							ATSApplication(f)
							ApDrill = str(input('Enter the Application name that you would like to drill down on: '))
							while 1:
								print(f'\nTop Application (Sessions) Drill-Down Menu\n')
								print(f'\nChoose from the following options on the Drill-down\n')
								print(f'\n1. Top Sources using the Application?')
								print(f'\n2. Top Destination where the application was accessed from?')
								print(f'\n3. Go Back to the previous menu')
								ApDrOpt = int(input('Enter the option # from above: '))
								if ApDrOpt == 1:
									ATSDrillSource(f,ApDrill)
								elif ApDrOpt == 2:
									ATSDrillDestination(f,ApDrill)
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
			print(f'\nTop Source Mode\n')
			ip_list = STSource(f,t)
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
					l = int(input('Enter the number of Top destinations required: '))
					STDrilldestination(drill_IP,f,l)
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
							STDrillApplication(f,drill_IP,'b')
						elif DrOpt == 2:
							print(f'\nTop Applications for source {drill_IP} by Session Count')
							STDrillApplication(f,drill_IP,'s')
						elif DrOpt == 3:
							break
						else:
							print(f'Wrong Input!!')
				elif sC == 3:
					l = 0
					break
				else:
					print(f'\nFunny Guy, eh? Please select the right option :)\n')
		if(format(args.destination) == 'True'):
			print(f'{format(args.destination)}')

	except KeyboardInterrupt:
		print(f'Keyboard Interrupt Detected! Thank You!.')


main()

	