class obj_fe:

	def __init__(self, size, objname, objbase, start, end):
		self.size = size
		self.objname = objname
		self.objbase = objbase
		self.xmin = start
		self.ymin = start
		self.xmax = end
		self.ymax = end

	def assign_name(self, name):
		self.objname = name