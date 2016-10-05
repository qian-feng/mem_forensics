import datetime
import re
import binascii
import volatility.obj as obj
from volatility.plugins.overlays.windows.windows import *
import pdb
win32 = (0x80000000,0x83000000)
win64 = ()

def check_boundary(objs):
	min_base, max_base = check_bases(objs)
	seg_boundary = check_segs(min_base, max_base)
	return seg_boundary

def check_bases(objs):
	min_base = 0xffffffff
	max_base = 0
	for name in objs:
		mibase = min(objs[name])
		mabase = max(objs[name])
		if min_base > mibase and mibase > 0x80000000:
			min_base = mibase
		if max_base < mabase:
			max_base = mabase

	return min_base, max_base

def check_segs(min_base, max_base):
	min_value = min_base % 0x80000000 & 0xff000000
	seg_min = 0x80000000 + min_value
	max_value = max_base % 0x80000000 & 0xff000000
	seg_max = 0x80000000 + max_value
	return (seg_min, seg_max)


def check_f(addr, kernel_address_space):
	val = obj.Object("unsigned int", addr, kernel_address_space)
	value = val.v()
	if str(type(value)).find('NoneObject')!=-1:
		return "d"
	re = check_pointer(value, kernel_address_space)
	if re:
		return re
	time = checkTime(addr, kernel_address_space)
	if time:
		return time

	inte = checkInteger(value)
	if inte:
		return inte

	st = checkString(value)
	if st:
		return st

	zero = checkZero(value)
	if zero:
		return zero
	return "d"


def check_pointer(value, kernel_address_space):
	p = obj.Object("unsigned int", value, kernel_address_space)
	if p == None:
		return False
	if p.v()%2==0:
		return "P"
	return False

def checkTime(addr, kernel_address_space):
	try:
		value = WinTimeStamp('WinTimeStamp', addr,kernel_address_space)
		x=datetime.datetime.fromtimestamp(value)
	except:
		return False
	if 2002 <= x.year <= 2016:
		return 'T'
	return False

# notice: we assume ASCII[32, 126] are strings. However, this could cause the problem.
# 1: Suppose x= 32, it is very likely that 32 is an Integer, which is mistakenly identifed as a string
def checkString(value):
	try:
		pattern = re.compile(r'[^a-z0-9.]')
		val = binascii.a2b_hex(hex(value)[2:-1])
		match = re.search(pattern, val)
		if match:
			return False
		#pdb.set_trace()
		return "S"
	except:
		return False

def checkInteger(value):
	if 0 < value < 10000:
		return 'I'
	return False

def checkZero(value):
	if value == 0:
		return "Z"
	return False
