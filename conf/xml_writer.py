import xml.etree.cElementTree as ET
import os
import pdb
import argparse

def writeXML(cseg, path):
	annotations = ET.Element("annotations")
	folder = ET.SubElement(annotations, "folder")
	folder.text = "Memset"

	filename = ET.SubElement(annotations,'filename')
	item = ET.SubElement(filename,'item')
	item.text = cseg.filename
    
	
	index = 1
	for obj_fe in cseg.objs:
		obj_id = 'object' + str(index)
		addObj(annotations, obj_fe, obj_id, cseg)
		index += 1
	
	obj_num = ET.SubElement(annotations, 'objnum')
	obj_num.text = str(cseg.obj_num)

	tree = ET.ElementTree(annotations)
	tree.write(path)


def addObj(annotations, obj_fe, obj_id, cseg):
	#pdb.set_trace()
	xmin_v = (obj_fe.objbase - cseg.start)/4 + 1
	ymin_v = xmin_v

	xmax_v = xmin_v + obj_fe.size/4 + 1
	ymax_v = xmax_v

	object1 = ET.SubElement(annotations, obj_id)
	name = ET.SubElement(object1, 'name')
	name.text = obj_fe.objname

	bndbox = ET.SubElement(object1, 'bndbox')
	xmin = ET.SubElement(bndbox, 'xmin')
	xmin.text = str(xmin_v)

	ymin = ET.SubElement(bndbox, 'ymin')
	ymin.text = str(ymin_v)

	xmax = ET.SubElement(bndbox, 'xmax')
	xmax.text = str(xmax_v)

	ymax = ET.SubElement(bndbox, 'ymax')
	ymax.text = str(ymax_v)


def readXML(path):
	filename = os.path.basename(path)
	filename = filename.replace('.xml','.png')
	tree = ET.parse(path)
	root = tree.getroot()
	for folder in root.iter("folder"):
		folder.text = "Memset"
		#folder.set('updated', 'yes')

	for item in root.iter("item"):
		item.text = filename
		#item.set("updated", "yes")
	tree.write(path)

def checkXML(path):
	#print path
	#fp = open(path + ".st", 'w')
	tree = ET.parse(path)
	root = tree.getroot()
	for num in root.iter("objnum"):
		num_i = int(num.text)

	for i in xrange(num_i):
		for obj in root.iter("object"+str(i+1)):
			objname = obj.findall("name")[0].text
			#pdb.set_trace()
			re = [int(item.text) for item in obj.iter("xmin") if int(item.text) in [0, 511, 512]]
			if len(re) != 0:
				#pdb.set_trace()
				print objname, re
				#fp.write(objname + "\t" + str(re[0]) + "\t" + path + '\n')

			re = [int(item.text) for item in obj.iter("xmax") if int(item.text) in [0, 511, 512]]
			if len(re) != 0:
				print objname, re
				#fp.write(objname + "\t" + str(re[0]) + "\t" + path + '\n')

	return False

def writeXML1(path):
	tree = ET.parse(path)
	root = tree.getroot()
	for item in root.iter("xmin"):
		value = int(item.text) + 1
		item.text = str(value)
	for item in root.iter("xmax"):
		value = int(item.text) + 1
		item.text = str(value)
	for item in root.iter("ymax"):
		value = int(item.text) + 1
		item.text = str(value)
	for item in root.iter("ymin"):
		value = int(item.text) + 1
		item.text = str(value)
	tree.write(path)

def parse_command():
	parser = argparse.ArgumentParser(description='encoding')
	parser.add_argument("--path", type=str, help="base directory")
	args = parser.parse_args()
	return args

if __name__ == '__main__':
	args = parse_command()
	path = args.path
	writeXML(path)
