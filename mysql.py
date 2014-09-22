#!/usr/bin/env python
#coding:UTF-8

import base
import subprocess

class Mysql(object):
	def __init__(self,mysql,user,passwd,sock,rep_delay_time = 0):
		self.mysql = mysql
		self.user = user
		self.passwd = passwd
		self.sock = sock
		self.rep_delay_time = rep_delay_time
	def checkslave(self):
		msg = ''
		ret = subprocess.Popen('%s -u%s -p%s -S %s -e "show slave status\G;"'%(self.mysql,self.user,self.passwd,self.sock),stdout=subprocess.PIPE,shell=True,stderr=subprocess.PIPE)
		err = ret.stderr.read()
		out = ret.stdout.readlines()
		if err or (not out):
			base.MQ.put("%s [ERROR] mysql -e执行异常!stderr:%s"%(base.TIME(),err.strip()))
			msg = '%sMysql -e执行异常!'%msg
		for i in out:
			if i.strip().startswith('Slave_IO_Running:') or i.strip().startswith('Slave_SQL_Running:'):
				if i.split(':')[1].strip() == 'No':
					base.MQ.put("%s [ERROR] Mysql主从复制失败!%s"%(base.TIME(),i.strip()))
					msg = '%sMysql主从复制失败'%msg
					break
			elif i.strip().startswith('Seconds_Behind_Master:'):
				count = int(i.split(':')[1].strip())
				if count > self.rep_delay_time:
					base.MQ.put("%s [ERROR] Mysql主从复制延迟!%s"%(base.TIME(),i.strip()))
					msg = '%sMysql主从复制延迟%s'%(msg,count)
		return msg	
