 #Copyright (C) <2012> <Syracuse System Security (Sycure) Lab> 
 #All rights reserved.
 #The XED library has its own license, which can be found in shared/xed2. 
 #------------------------------------------------------------------------ 
 #author = qian
 #email = qifeng@syr.edu
 
import traceback
import volatility.commands as commands
import volatility.obj as obj
import volatility.utils as utils
import volatility.scan as scan
import volatility.win32.tasks as tasks
import volatility.plugins.moddump as moddump
import volatility.plugins.modscan as modscan
import volatility.plugins.volshell as volshell
import volatility.plugins.common as common
import volatility.plugins.malware.threads as threads
import volatility.plugins.filescan as filescan
import volatility.plugins.mac.pslist as macpslist
import volatility.plugins.mac.pstasks as macpstasks
from volatility.plugins.conf.win_config import *
from volatility.plugins.conf.feature import *
from volatility.plugins.conf.obj_fe import *
from volatility.plugins.conf.csegment import *

#import networkx as nx
import sys
import pdb
import os
#from subprocess import call,Popen
import subprocess
import cPickle as pickle
from operator import itemgetter
import volatility.debug as debug
import bisect

#Temoraries
heap_objs = []
heap_objs_starts = []

#(src_addr, dst_addr, src_offset, dst_offset)
obj_ptrs = {}
obj_base = {}
obj_size = {}
base_obj = {}

class Mlabeling(common.AbstractWindowsCommand):
	'''Grabeach address in the given memory dump'''

	def __init__(self, config, *args):
		common.AbstractWindowsCommand.__init__(self, config, *args)
		self.kernel_address_space = None
		self.seg_threshold = (0x80000000,0x83000000)

	# for windows
	def check_pslist(self):
		"""Enumerate processes from PsActiveProcessHead"""
		all_tasks = list(tasks.pslist(self.kernel_address_space))
		procs = dict((p.obj_offset, (p,p.size())) for p in all_tasks)
		return procs

	def check_threads(self):
		threds = dict((ethread[0].obj_offset, (ethread[0], ethread[0].size())) for ethread in threads.Threads(self._config).calculate() if ethread[0].obj_offset > 0x80000000)
		return threds

	def check_drivers(self):
		drivs = dict((v[1].obj_offset, (v[1], v[1].size())) for v in filescan.DriverScan(self._config).calculate())
		return drivs

	def check_files(self):
		files = dict((v[1].obj_offset,(v[1], v[1].size())) for v in filescan.FileScan(self._config).calculate())
		return files

	# for mac
	def check_mac_pslist(self):
		procs = dict((v.obj_offset,(v, v.size())) for v in macpslist.mac_pslist(self._config).calculate())
		return procs

	def check_mac_tasks(self):
		procs = dict((v.obj_offset,(v, v.size())) for v in macpstasks.mac_tasks(self._config).obtainTasks())
		return procs


	def forwindows(self):
		objs = {}
		pdb.set_trace()
		procs = self.check_pslist()
		#threds = self.check_threads()
		#drivers = self.check_drivers()
		#files = self.check_files()
		objs['process'] = procs
		#objs['thread'] = threds
		#objs['drivers'] = drivers
		#objs['file'] = files
		return objs

	def formac(self):
		objs = {}
		procs = self.check_pslist()


	def objlabeling(self):
		objs = self.forwindows()
		#self.forlinux()
		#self.formac()
		return objs

	def checkContinue(self, sets, seg_b):
		start = sets[0]
		end = sets[1] + sets[0]
		if sets[0] < seg_b[0] and (sets[0] + sets[1]) > seg_b[1]:
			return True

		if start <= seg_b[1] <= end:
			return True

		if start <= seg_b[0] <= end:
			return True

		if seg_b[0] <= start <= seg_b[1]:
			return True

		if seg_b[0] <= end <= seg_b[1]:
			return True

		return False


	def fe_memory(self, seg_b):
		segments_fe = {}
		segment_adr = {}
		segment_str = {}
		available_address = self.kernel_address_space.get_available_addresses()
		segments = [(start,size) for start,size in available_address]
		#segments = [(start,size) for start,size in available_address if start == 2162163712]
		print len(segments)
		print seg_b
		#pdb.set_trace()
		for sets in segments:
			start = sets[0]
			size = sets[1]
			if not self.checkContinue(sets, seg_b):
				continue
			memory_structure=""
			print start
			i = 0
			memory_structure=''.join([check_f(addr, self.kernel_address_space) for addr in range(start, start+size,4)])
			'''
			print i/(size/4.0)
			i = i+1
			addr_type = check_f(addr, self.kernel_address_space)
			memory_structure += addr_type
			'''
			segment_adr[start]=(start +size)
			segment_str[start] = memory_structure
		segments_fe['addr'] = segment_adr
		segments_fe['feature'] = segment_str
		return segments_fe


	def fe_objs(self, objs, segments_fe):
		obj_fes = []
		csegs = csegments()
		segs = segments()
		for objname in objs:
			seg_start = None
			for base in objs[objname]:
				size = objs[objname][base][1]
				#pdb.set_trace()
				cseg, obj_fe = self.obtainFE(base, objname, size, segments_fe, seg_start)
				if cseg:
					obj_fes.append(obj_fe)
					csegs.add_cseg(cseg)
		#pdb.set_trace()
		segs.segmentToPic(obj_fes, segments_fe)
		csegs.assign_objs_to_list(obj_fes)
		return csegs, segs


	def checkSeg(self, base, segments_fe):
		for seg_start in segments_fe['addr']:
			seg_end = segments_fe['addr'][seg_start]
			#pdb.set_trace()
			if seg_start <= base <= seg_end:
				return seg_start
		return False

	def getRange(self, size):
		return (512 - size/4)/2


	def obtainFE(self, base, objname, size, segments_fe, seg_start):
		image_range = self.getRange(size)
		if not seg_start:
			seg_start = self.checkSeg(base, segments_fe)
			if not seg_start:
				return False, False

		start_offset = (base - seg_start)/4 - image_range
		end_offset = (base + size - seg_start)/4 + image_range
		fe = segments_fe['feature'][seg_start][start_offset:end_offset]
		#pdb.set_trace()
		obj = obj_fe(size, objname, base, image_range, image_range + size/4)
		cseg = csegment(seg_start + start_offset * 4, seg_start + end_offset*4, seg_start)
		cseg.add_obj(obj)
		cseg.set_centerObj(obj)
		cseg.assign_fe(fe)
		return cseg, obj

	def calculate(self):
		filename = os.path.basename(self._config.LOCATION)
		path = os.path.join(self._config._path, filename)
		if not os.path.exists(path):
			os.makedirs(path)

		self.kernel_address_space = utils.load_as(self._config)
		objs = self.objlabeling()
		#pdb.set_trace()
		'''
		seg_b = check_boundary(objs)
		segments_fe = self.fe_memory(seg_b)
		print "finishing segment labeling....."
		#pdb.set_trace()
		pickle.dump(segments_fe, open(path + filename + ".segments_fe", "w"))
		'''
		segments_fe = pickle.load(open(self._config._path + "/" + filename + ".segments_fe", "r"))
		#pdb.set_trace()
		print "obj labeling...."
		csegs, segs = self.fe_objs(objs, segments_fe)
		#pdb.set_trace()
		csegs.dump(path, filename)
		segs.dump(path, filename)
		del csegs
		del segments_fe
		del objs

		#pdb.set_trace()
		print "s"
		
	def render_text(self, outfd, data):
		if data!=None:
			outfd.write(data)
