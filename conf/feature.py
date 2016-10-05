
class feature:
	def __init__(self, filename):
		self.image_name = filename
		self.segments = None
		self.obj_features = None

	def fe_memory(self, segment_adr, segment_str):
		self.segments['info'] = segment_adr
		self.segments['feature'] = segment_str

	def fe_objs(self, objs):
		self.obj_features