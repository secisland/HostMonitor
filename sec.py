#!/usr/bin/env python
#coding:UTF-8

from pyinotify import ProcessEvent,WatchManager,Notifier,IN_CREATE,IN_MODIFY,IN_DELETE,WatchManagerError,PyinotifyError
import os
import re
import base
import hashlib
import subprocess

class CheckLogin(object):
	def __init__(self,access_ip_list):
		self.access_ip_list = access_ip_list
		self.pattern = re.compile('\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}') 
		if os.path.exists('/var/log/secure'):
			self.f = open('/var/log/secure')
			self.f_pos = os.path.getsize('/var/log/secure')
			self.f.seek(self.f_pos)
		else:
			self.f = None
			self.f_pos = 0
			base.MQ.put("%s [ERROR] 系统日志文件:/var/log/secure 丢失!"%base.TIME())
	def check(self):
		count = []
		try:
			pos = os.path.getsize('/var/log/secure')
			if pos < self.f_pos:
				self.close()
				self.f = open('/var/log/secure')
				self.f_pos = 0
				self.f.seek(self.f_pos)
				return
			records = self.f.readlines()
			if records:
				self.f_pos = os.path.getsize('/var/log/secure')
			for record in records:
				if 'Accepted' in record:
					base.MQ.put("%s [DEBUG] CheckLogin Accepted记录：%s"%(base.TIME(),record))
					timestamp_year = base.time.strftime('%Y',base.time.localtime())
					timestamp_log = "%s%s"%(record[:16],timestamp_year)
					timestamp_now_sec = base.time.time()
					timestamp_log_sec = base.time.mktime(base.time.strptime(timestamp_log,"%b %d %H:%M:%S %Y"))
					find_ip = self.pattern.findall(record)
					for i in find_ip:
						t =timestamp_now_sec - timestamp_log_sec
						#print "时间判断:%s,%s"%(t,i)
						if (timestamp_now_sec - timestamp_log_sec) < 10:
							if not i in self.access_ip_list:
								#print "%s IP:%s login accepted!"%(base.TIME(),i)
								base.MQ.put("%s [WARNING] IP:%s login!"%(base.TIME(),i))
								count.append(i)
			if count:
				base.ALARM_DICT['sec'][0] = "IP:%s异常登陆!"%(','.join(count))
		except Exception,e:
			base.MQ.put("%s [ERROR] 读取日志文件:/var/log/secure 出错!%s"%(base.TIME(),e))
	def close(self):
		if self.f:
			self.f.close()

#定义事件处理器
class FSMonitor(ProcessEvent):
	def process_default(self,event):
		if event.name.endswith('.swp') or event.name.endswith('.swx') or event.name.endswith('.swpx') or event.name.endswith('~') or event.name.endswith('.swo') or ('prelink' in event.name) :
			# print 'tmpfile:%s'%event.name
			pass
		elif event.maskname == 'IN_MODIFY':
			base.MQ.put('%s [WARNING] %s Modified! EVENT NAME:%s'%(base.TIME(),event.pathname,event.name))
			base.ALARM_DICT['sec'][1]  += 1
		elif event.maskname == 'IN_DELETE':
			base.MQ.put('%s [WARNING] %s Deleted!'%(base.TIME(),event.pathname))
			base.ALARM_DICT['sec'][1] += 1

	def process_IN_MODIFY(self,event):
		self.process_default(event)

	def process_IN_DELETE(self,event):
		self.process_default(event)

class CheckHash(object):
	def __init__(self,fs):
		self.hash = {}
		for f in fs:
			self.hash.setdefault(f,self.hash_file(f))
		self.iptables = self.hash_iptables()

	def hash_iptables(self):
		return	subprocess.Popen("iptables -nL|md5sum|awk '{print $1}'",stdout=subprocess.PIPE,shell=True).stdout.readline().strip()
	
	def hash_file(self,f):
		if os.path.exists(f):
			return hashlib.md5(open(f).read()).hexdigest()	
		else:
			base.MQ.put("%s [ERROR] 监控文件不存在:%s"%(base.TIME(),f))
	def check(self):
		ret = []
		tmp_hash = None
		for f in self.hash.keys():
			tmp_hash =  self.hash_file(f)
			if self.hash[f] == tmp_hash:
				pass
			else:
				ret.append(f)
				self.hash[f]=tmp_hash
		tmp_hash = self.hash_iptables()
		if self.iptables == tmp_hash:
			pass
		else:
			ret.append('iptables')
			self.iptables = tmp_hash
		return ret
			
if __name__=='__main__':
	#定义监视的事件
	mask = IN_MODIFY | IN_DELETE
	path = ['/etc', '/usr/local/sbin', '/usr/local/bin', '/sbin', '/bin', '/usr/sbin', '/usr/bin']
	m_file = ['/root/.bash_profile','/root/.bash_logout','/root/.bashrc']

	#监视管理器实例
	wm = WatchManager()
	wm.add_watch(path,mask)

	#创建事件监视器
	notifier = Notifier(wm,FSMonitor())

	print 'start monitoring %s with mask ox%08x' %(path,mask)

	checkhash = CheckHash(m_file)
	while True:
		try:
			notifier.process_events()
			if notifier.check_events(60000):
				notifier.read_events()
			hash = checkhash.check()
			#print 'checkhash result!%s'%hash
			if hash:
				for i in hash:
					print '%s modified!'%i
		except KeyboardInterrupt:
			print 'stop monitoring...'
			notifier.stop()
			break
		except Exception,err:
			print err
