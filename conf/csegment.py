from volatility.plugins.conf.obj_fe import *
from volatility.plugins.conf.xml_writer import *
import pdb
import os
class csegment:

	def __init__(self, start, end, seg_base):
		self.objs = {}
		self.filepath = None
		self.center_obj = None
		self.obj_num = 0
		self.fe = None
		self.start = start
		self.end = end
		self.seg_base = seg_base
		self.id = None
		self.filename = None

	def assign_fe(self, fe):
		self.fe = fe

	def set_centerObj(self, obj):
		self.center_obj = obj

	def add_obj(self, obj_fe):
		self.objs[obj_fe] = 1
		self.obj_num += 1

	def assign_objs(self, obj_fes):
		self.objs = obj_fes

	def assign_obj_num(self, obj_num):
		self.obj_num = obj_num

	def assign_filepath(self, filepath):
		self.filepath = filepath

	def assign_id(self, id_):
		self.id = id_

	def isIn(self, obj):
		return obj in self.objs

	def __len__(self):
		return len(self.objs)

	def dump(self, full_path):
		fp = open(full_path+".png",'w')
		fp.write(self.fe)
		fp.close()


class csegments:

	def __init__(self):
		self.csegment_list = {}

	def add_cseg(self, cseg):
		self.csegment_list[(cseg.start, cseg.end)] = cseg

	def assign_objs_to_list(self, objs):
		for obj in objs:
			self.assign_obj(obj)

	def assign_obj(self, obj):
		csegs = [self.csegment_list[v] for v in self.csegment_list if v[0] <= obj.objbase and (obj.objbase + obj.size) <= v[1]]
		for cseg in csegs:
			if not cseg.isIn(obj):
				cseg.add_obj(obj)

	def __len__(self):
		return len(self.csegment_list)


	def dump(self, path, filename):
		folder_name = filename.replace(".","_")
		for key in self.csegment_list:
			cseg = self.csegment_list[key]
			filename = "%s_%d.%s.%d.%d.%d"%(folder_name,cseg.seg_base, cseg.center_obj.objname, cseg.start, cseg.end, (cseg.start-cseg.seg_base))
			cseg.filename =filename+".png"
			cseg.filepath = os.path.basename(path)
			full_path = os.path.join(path, filename)
			cseg.dump(full_path)
			#pdb.set_trace()
			writeXML(cseg, full_path+".xml")


class segments:
	def __init__(self):
		self.segments = {}

	def add_cseg(self, cseg):
		self.segments[(cseg.start, cseg.end)] = cseg

	def segmentToPic(self, objs, segments_fe):
		obj_fes = []
		for seg_start in segments_fe['addr']:
			seg_end = segments_fe['addr'][seg_start]
			fe = segments_fe['feature'][seg_start]
			cseg = csegment(seg_start, seg_end, 0)
			cobjs = [obj for obj in objs if seg_start <= obj.objbase and (obj.objbase + obj.size) <= seg_end]
			cseg.assign_objs(cobjs)
			cseg.assign_fe(fe)
			cseg.assign_obj_num(len(cseg))
			self.add_cseg(cseg)

	def dump(self, path, filename):
		folder_name = filename.replace(".","_")
		for key in self.segments:
			cseg = self.segments[key]
			filename = "%s_%d.%s.%d.%d.%d"%(folder_name,cseg.seg_base, "seg", cseg.start, cseg.end, (cseg.start-cseg.seg_base))
			cseg.filename =filename+".png"
			cseg.filepath = os.path.basename(path)
			full_path = os.path.join(path, filename)
			cseg.dump(full_path)
			writeXML(cseg, full_path+".xml")
		