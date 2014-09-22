#!/usr/bin/env python
#coding:utf-8

import time
import re
import Queue
import ConfigParser
import os

MQ = Queue.Queue(4096)
ALARM_DICT = {
	'cpu':'',
	'mem':'',
	'disk':'',
	'inode':'',
	'net':'',
	'proc':'',
	'sec':['',0],
	'mysql':'',
	'redis':'',
	'nginx':'',
	'game':'',
	'custom':'',
	'log':''
	}

def TIME():
	return time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))

def Config(*args):
	l = len(args)
	conf = ConfigParser.ConfigParser()
	conf.read('config')
	try:
		if l == 1:
			return conf.items(args[0])
		elif l == 2:
			return conf.get(args[0],args[1])
	except (ConfigParser.NoSectionError,ConfigParser.NoOptionError) ,e: 
		MQ.put("%s [ERROR] 配置文件读取错误：%s"%(TIME(),e))
		raise IOError

def threshold(thre,key,msg,alarm_flag,single=True):
	#print "Threshold call... %s %s"%(msg,key)
	info = '%s异常!%s'%(msg,key)
	low = thre.split(',')[0].strip()
	high = thre.split(',')[1].strip()
	if low.startswith('0') and ( key > int(high)):
		#print "判断：%s %s"%(msg,key)
		if single:
			MQ.put('%s [WARNING] %s'%(TIME(),info))
			ALARM_DICT[alarm_flag] = info
		else:
			return info
	elif not low.startswith('0'):
		if (key < int(low)) or (key > int(high)):
			if single:
				MQ.put('%s [WARNING] %s'%(TIME(),info))
				ALARM_DICT[alarm_flag] = info
			else:
				return info
	else:
		if single:
			ALARM_DICT[alarm_flag] = ''
		else:
			return ''

class ReadLog(object):
	def __init__(self , fn , patt):
		self.log = fn
		self.f_handle = None
		self.f_pos = 0
		self.patt = re.compile(patt)
		if os.path.exists(fn):
			self.f_handle = open(self.log)
			self.f_pos = os.path.getsize(self.log)
			self.f_handle.seek(self.f_pos)
		else:
			MQ.put("%s [ERROR] 日志文件:%s 丢失!"%(TIME(),self.log))
			
	def run(self):
		ret = ''
		try:
			pos = os.path.getsize(self.log)
			if pos < self.f_pos:
				self.close()
				self.f_handle = open(self.log)
				self.f_pos = 0
				self.f.seek(self.f_pos)
				return
			records = self.f_handle.readlines()
			if records:
				self.f_pos = os.path.getsize(self.log)
				for record in records:
					if self.patt.search(record):
						msg = record
						for i in [' [debug] ',' [info] ',' [warning] ',' [error] ',' [critical] ']:
							if i in msg.lower():
								msg = msg.lower().replace(i,' ')
						MQ.put("%s [ERROR] %s日志异常!%s"%(TIME(),self.log,msg))
						ret = '%s%s'%(ret,msg)
			if ret:
				return "%s日志异常!%s"%(self.log,ret[:80])
			else:
				return ret
		except Exception,e:
			MQ.put("%s [ERROR] %s日志监控出错! %s"%(TIME(),self.log,e))
			ALARM_DICT['log'] = "%s日志监控出错"%self.log
			return ret[:80]
