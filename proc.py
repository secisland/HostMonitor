#!/usr/bin/env python
#coding:utf-8

import os
import subprocess
import base

def CheckProc(proc_list):
	count = []
	try:
		for i in proc_list:
			proc_attr = i[1].split(':')
			try:
				proc_exe = proc_attr[0].strip()
				proc_port = proc_attr[1].strip()
				# 进程退出，自动启动
				proc_reload = proc_attr[2].strip()
			except Exception,e:
				base.MQ.put('%s [ERROR] %s 进程监控配置格式出错:%s'%(base.TIME(),i[0],e))
				continue
			if proc_port:
				pid = os.popen("lsof -i4:%s|grep LISTEN|sed -n '1p'|awk '{print $2}'"%proc_port).read().strip()
				if os.path.exists('/proc/%s/exe'%pid) and (proc_exe == os.readlink('/proc/%s/exe'%pid)):
					continue
				else:
					#print "进程退出:%s"%i[0]
					base.MQ.put('%s [WARNING] %s 进程退出!'%(base.TIME(),i[0]))
					count.append(i[0])
					if proc_reload:
						subprocess.Popen(proc_reload,shell=True)
						base.MQ.put('%s [INFO] %s:执行进程自动重启!'%(base.TIME(),i[0]))
			else:
				pids = os.popen("ps -eo pid,cmd|grep %s|awk '{print $1}'"%i[0]).read().strip().split(os.linesep)
				base.MQ.put("%s [DEBUG] 进程PIDS:%s,%s,%s"%(base.TIME(),pids,i[0],proc_exe))
				exes = [os.readlink('/proc/%s/exe'%pid) for pid in pids if os.path.exists('/proc/%s/exe'%pid)]
				if proc_exe not in exes:
					base.MQ.put('%s [WARNING] %s 进程退出!'%(base.TIME(),i[0]))
					count.append(i[0])
					if proc_reload:
						subprocess.Popen(proc_reload,shell=True)
						base.MQ.put('%s [INFO] %s:执行进程自动重启!'%(base.TIME(),i[0]))
					continue
		if count:
			base.ALARM_DICT['proc'] = '%s 进程退出!'%(','.join(count))
		else:
			base.ALARM_DICT['proc'] = ''
	except Exception,e:
		base.MQ.put('%s [ERROR] 进程监控程序出错:%s'%(base.TIME(),e))
