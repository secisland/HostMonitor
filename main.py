#!/usr/bin/env python
#coding:utf-8
#_DEBUG=True

import os
import sys
import socket
import threading
import fcntl
import struct
import ConfigParser
import json
import urllib
import logging
import base
import sec
import proc
import mysql
import system
#import pdb

def GetIP(interface='eth0'):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915, struct.pack('256s', interface[:15]))[20:24])

def Alert(url,msg):
	try:
		req = urllib.urlopen(url,data=msg)
	except IOError,e:
		base.MQ.put("%s [CRIT] 提交报警任务出错,请确认url地址可访问！:%s url=%s msg: %s"%(base.TIME(),e,url,msg))
		return False
	try:
		ret = json.loads(req.read())
	except ValueError,e:
		base.MQ.put('%s [CRIT] 报警API接口返回值异常，可能非json格式:%s'%(base.TIME(),e))
		return False
	base.MQ.put('%s [DEBUG] 提交报警API URL地址json结果:%s'%(base.TIME(),ret))
	httpcode = str(req.getcode())
	if  httpcode.startswith('2'):
		if ret['content'] in ("server status ok","success","auto repaired"):
			return True
		elif ret['content']['message'] != 'alarm is alarming' :
			base.MQ.put("%s [CRIT] 提交报警任务失败! url=%s msg: %s ret:%s"%(base.TIME(),url,msg,ret))
			return False
	else:
		base.MQ.put("%s [CRIT] 提交报警任务失败!POST返回状态码:%s url=%s msg: %s"%(base.TIME(),httpcode,url,msg))
		return False
	return True

def thread_base(conf):
	'''
	负责写日志及提交信息到告警接口,日志格式说明:
	xxxx-xx-xx xx:xx:xx [标记] 消息
	-------------------		|
	    |___日期及时间		|
							|
							+---- [DEBUG]  	调试信息
							|____ [INFO] 	系统运行状态信息
							|____ [WARNING] 	监控到系统出现异常
							|____ [ERROR] 	一般程序错误信息
							|____ [CRITICAL]	严重错误,如提交警失败
	'''
	
	print "thread_base running..."

	try:
		log = conf.get('base','logfile')
		apiurl = conf.get('base','apiurl')
		log_level = conf.get('base','log_level')
	except Exception,e:
		print "%s [ERROR] 配置文件错误，monitor_base线程退出!%s"%(base.TIME(),e)
		sys.exit(1)
	d_log_level = {"DEBUG":10,"INFO":20,"WARNING":30,"ERROR":40,"CRITICAL":50}
	ip_arg = "ip=%s"%GetIP()
	base.MQ.put('%s [DEBUG] 本机IP地址：%s'%(base.TIME(),ip_arg))
	if log:
		logging.basicConfig(filename=log,format='%(message)s',filemode='a',level=d_log_level[log_level])
	else:
		logging.basicConfig(filename='log/monitor.log',format='%(message)s',filemode='a',level=d_log_level[log_level])
	while True:
		flag = base.time.time()
		uri_args = [ip_arg]
		sec_arg = ''
		try:
			while (base.time.time()-flag)<59:
				if not base.MQ.empty():
					msg = base.MQ.get()
					if '[DEBUG]' in msg:
						logging.debug(msg)
					elif '[INFO]' in msg:
						logging.info(msg)
					elif '[WARNING]' in msg:
						logging.warning(msg)
					elif '[ERROR]' in msg:
						logging.error(msg)
					elif '[CRIT]' in msg:
						logging.critical(msg)
				else:
					base.time.sleep(1)
			#print "时间差：%s"%(base.time.time()-flag)
			if apiurl:
				for i in base.ALARM_DICT.keys():
					if base.ALARM_DICT[i] and (i != 'sec'):
						uri_args.append('%s=%s'%(i,base.ALARM_DICT[i]))
				if base.ALARM_DICT['sec'][0]:
					sec_arg = base.ALARM_DICT['sec'][0]
				if base.ALARM_DICT['sec'][1]:
					sec_arg = '%s有%s个文件被修改!'%(sec_arg,base.ALARM_DICT['sec'][1])
				if sec_arg:
					uri_args.append('sec=%s'%sec_arg)
				logging.debug('POST:%s'%uri_args)
				if Alert(apiurl,'&'.join(uri_args)):
					base.MQ.put('%s [INFO][POST] %s %s'%(base.TIME(),apiurl,'&'.join(uri_args)))
					base.ALARM_DICT['sec'] = ['',0]
			base.time.sleep(1)
		except IOError,err:
			print 'monitor thread-sec error! %s'%err
			base.MQ.put("%s [ERROR] monitor_base线程异常错误!%s"%(base.TIME(),err))
			print 'thread-sec exit...'
			os.kill(os.getpid(),9)
			sys.exit(1)

def thread_system(conf):
	print "thread_system running..."
	try:
		threshold_cpu = conf.get('system','cpu')
		threshold_cpu_core = conf.get('system','cpu_core')
		threshold_mem = conf.get('system','mem')
		threshold_disk = conf.get('system','disk')
		threshold_inode = conf.get('system','inode')
		threshold_load = conf.get('system','load')
		threshold_net = conf.get('system','net')
	except Exception,e:
		base.MQ.put("%s [ERROR] 配置文件错误，monitor_system线程退出!%s"%(base.TIME(),e))
		base.time.sleep(1)
		sys.exit(1)
	sys_stat = system.SystemStat(cpu_core = threshold_cpu_core)
	
    while True:
		base.threshold(threshold_mem , sys_stat.get_mem_usage() , "内存使用率" , 'mem')
		base.threshold(threshold_load , sys_stat.get_load() , "系统负载" , 'load')
		disk = sys_stat.get_disk_usage()
		mulmsg = ''
		for i in disk.keys():
			mulmsg = "%s%s"%(mulmsg,base.threshold(threshold_disk , disk[i] , "挂载点:%s 使用率"%i , 'disk',single = False))
			base.MQ.put('%s [DEBUG] 挂载点:%s 使用率:%s%%'%(base.TIME(),i,disk[i]))
		if mulmsg:
			base.MQ.put('%s [WARNING] %s'%(base.TIME(),mulmsg))
			base.ALARM_DICT['disk'] = mulmsg
		inode = sys_stat.get_inode_usage()
		mulmsg = ''
		for i in inode.keys():
			mulmsg = "%s%s"%(mulmsg,base.threshold(threshold_inode , inode[i] , "文件系统:%s inode使用率"%i , 'inode',single = False))
			base.MQ.put('%s [DEBUG] 文件系统:%s 使用率:%s%%'%(base.TIME(),i,inode[i]))
		if mulmsg:
			base.MQ.put('%s [WARNING] %s'%(base.TIME(),mulmsg))
			base.ALARM_DICT['inode'] = mulmsg	
		dict_cpu1 = sys_stat._read_cpu_usage()
		base.MQ.put("%s [DEBUG] DICT_CPU1:%s"%(base.TIME(),dict_cpu1))
		dict_net1 = sys_stat._read_net_rate()
		base.MQ.put("%s [DEBUG] DICT_NET1:%s"%(base.TIME(),dict_net1))
		base.time.sleep(sys_stat.interval)

		dict_cpu2 = sys_stat._read_cpu_usage()
		base.MQ.put("%s [DEBUG] DICT_CPU2:%s"%(base.TIME(),dict_cpu2))
		dict_net2 = sys_stat._read_net_rate()
		base.MQ.put("%s [DEBUG] DICT_NET2:%s"%(base.TIME(),dict_net2))
		if threshold_cpu_core.strip().lower() == 'false':
			cpuper = int(100*((dict_cpu2[0][2] - dict_cpu1[0][2])/float(dict_cpu2[0][1] - dict_cpu1[0][1])))
			base.MQ.put('%s [DEBUG] %s 使用率:%s%%'%(base.TIME(),dict_cpu2[0][0],cpuper))
			base.threshold(threshold_cpu , cpuper , "%s使用率"%dict_cpu2[0][0] , 'cpu')
		else:
			num = len(dict_cpu2)
			mulmsg = ''
			for i in range(num):
				cpuper = int(100*((dict_cpu2[i][2] - dict_cpu1[i][2])/float(dict_cpu2[i][1] - dict_cpu1[i][1])))
				base.MQ.put('%s [DEBUG] %s 使用率:%s%%'%(base.TIME(),dict_cpu2[i][0],cpuper))
				mulmsg = "%s%s"%(mulmsg,base.threshold(threshold_cpu , cpuper , "%s使用率"%dict_cpu2[i][0] , 'cpu', single = False))
			if mulmsg:
				base.MQ.put('%s [WARNING] %s'%(base.TIME(),mulmsg))
				base.ALARM_DICT['cpu'] = mulmsg
		for i in dict_net2.keys():
			netflow=int((long(dict_net2[i][0])+long(dict_net2[i][1])-long(dict_net1[i][0])-long(dict_net1[i][1]))/1024.0/1024.0/sys_stat.interval)*8
			base.MQ.put('%s [DEBUG] %s 速率:%sMbps!'%(base.TIME(),i,netflow))
			base.threshold(threshold_net , netflow , "%s流量(Mbps)"%i , 'net')
		base.time.sleep(30)

def thread_sec(conf):
	print "thread_sec running..."
	#初始化变量
	#定义监视的事件
	#pdb.set_trace()
	mask = sec.IN_MODIFY | sec.IN_DELETE

	try:
		path = conf.get('sec','md_sys_path').split(':')
		path.extend(conf.get('sec','md_app_path').split(':'))

		m_files = conf.get('sec','md_file').split(':')
		access_ip_list = conf.get('sec','access_ip_list').split(":")
	except Exception,e:
		base.MQ.put("%s [ERROR] 配置文件错误,monitor_sec线程退出!%s"%(base.TIME(),e))
		base.time.sleep(1)
		sys.exit(1)
	#监视管理器实例
	wm = sec.WatchManager()
	wm.add_watch(path,mask,rec=True)

	#创建事件监视器
	notifier = sec.Notifier(wm,sec.FSMonitor())
	#print 'start filesystem monitoring %s with mask ox%08x' %(path,mask)
	base.MQ.put("%s [INFO] start filesystem monitoring %s with mask ox%08x"%(base.TIME(),path,mask))

	checkhash = sec.CheckHash(m_files)
	checklogin = sec.CheckLogin(access_ip_list)
	while True:
		try:
			notifier.process_events()
			if notifier.check_events(10000):
				notifier.read_events()
			hash = checkhash.check()
			base.MQ.put('%s [DEBUG] 文件监控checkhash result!%s'%(base.TIME(),hash))
			for i in hash:
				#print '%s modified!'%i
				base.MQ.put("%s [WARNING] %s Modified!"%(base.TIME(),i))
			base.ALARM_DICT['sec'][1] += len(hash)
		except Exception,err:
			#print "%s 文件系统监控出错:%s"%(base.TIME(),err)
			base.MQ.put("%s [ERROR] 文件系统监控出错:%s"%(base.TIME(),err))
		checklogin.check()

def thread_proc(conf):
	print "thread_proc running..."
	try:
		proc_list = conf.get('proc')
	except Exception,e:
		base.MQ.put("%s [ERROR] 配置文件错误,monitor_proc线程退出!%s"%(base.TIME(),e))
		base.time.sleep(1)
		sys.exit(1)
	while True:
		proc.CheckProc(proc_list)
		base.time.sleep(60)


def thread_mysql(conf):
	print "thread_mysql running..."
	try:
		mysqlbin = conf.get('mysql','mysql')
		sock = conf.get('mysql','sock')
		errlog = conf.get('mysql','errlog')
		pattern = conf.get('mysql','pattern')
		role = conf.get('mysql','role')
		user = conf.get('mysql','user')
		passwd = conf.get('mysql','passwd')
		rep_delay_time = conf.get('mysql','rep_delay_time')
	except Exception,err:
		print 'monitor thread-mysql error! %s'%err
		base.MQ.put("%s [ERROR] monitor_mysql线程配置错误!%s"%(base.TIME(),err))
		print 'thread-mysql exit...'
		os.kill(os.getpid(),9)
		sys.exit(1)
	if role.lower() == 'slave':
		slave = mysql.Mysql(mysqlbin,user,passwd,sock,rep_delay_time)
	else:
		slave = None
	readlog = base.ReadLog(errlog,pattern)
	while True:
		msg = ''
		try:
			if slave:
				msg = "%s%s"%(msg,slave.checkslave())
			msg = "%s%s"%(msg,readlog.run())
			base.ALARM_DICT['mysql'] = msg
		except Exception,e:
			base.MQ.put("%s [ERROR] monitor_mysql线程异常错误!%s"%(base.TIME(),e))
			base.ALARM_DICT['mysql'] = "%s monitor_mysql线程异常错误!"%msg
		base.time.sleep(60)

def thread_custom(conf):
	pass

class Config(object):
	def __init__(self):
		self.config = ConfigParser.ConfigParser()
		self.config.read('config')
	def get(self,*args):
		l = len(args)
		try:
			if l == 1:
				return self.config.items(args[0])
			elif l == 2:
				return self.config.get(args[0],args[1])
       	except (ConfigParser.NoSectionError,ConfigParser.NoOptionError) ,e:
			base.MQ.put("%s [ERROR] 配置文件读取错误：%s"%(base.TIME(),e))
	def get_sections(self):
		return self.config.sections()
		
def main(conf):
	#conf = Config()
	threads = []
	
	for i in conf.get_sections():
		threads.append(threading.Thread(name='monitor_%s'%i, target=eval('thread_%s'%i),args=(conf,)))
	for i in threads:
		i.setDaemon(True)
	for i in threads:
		i.start()
	while True:
		try:
			base.time.sleep(60)
			thread_acount = threading.activeCount()
			base.MQ.put("%s [DEBUG] 总线程数:%s[%s]，当前线程数:%s"%(base.TIME(),len(threads)+1,threads,thread_acount))
			if len(threads)+1 >  thread_acount:
				if "monitor_agent进程异常" not in base.ALARM_DICT['proc']:
					base.ALARM_DICT['proc'] = 'monitor_agent进程异常!%s'%base.ALARM_DICT['proc']
		except KeyboardInterrupt:
			print "exit..."
			break
			
def daemon(conf):
	path = os.path.abspath(os.curdir)
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(1)
	except OSError,e:
		print >>sys.stderr, "fork #1 failed:%d (%s)"%(e.errno,e.strerror)
		sys.exit(1)

	os.chdir(path)
	os.setsid()
	os.umask(0)
	
	try:
		pid = os.fork()
		if pid > 0:
			print "Daemon PID %d"%pid
			open(os.path.join('%s/run'%path,'monitor.pid'),'w').write("%s"%pid)
			sys.exit(0)
	except OSError,e:
		print >>sys.stderr, "fork #2 failed: %d (%s)"%(e.errno,e.strerror)
		sys.exit(1)
	main(conf)

if __name__=='__main__':
	conf = Config()
	try:
		is_daemon = conf.get('base','daemon')
	except Exception,e:
		base.MQ.put("%s [ERROR] 配置文件读取{base}-{daemon}错误：%s"%(base.TIME(),e))
		print "%s [ERROR] 配置文件读取{base}-{daemon}错误：%s"%(base.TIME(),e)
		sys.exit(1)
	try:
		pid = open('%s/run/monitor.pid'%os.path.abspath(os.curdir)).read().strip()
		if os.path.exists('/proc/%s'%pid):
			print '进程正在运行...'
			sys.exit(0)
	except Exception,e:
		print '启动异常:%s'%e
	if is_daemon.lower().strip() == 'true':
		daemon(conf)
	else:
		print "Main PID:%s"%os.getpid()
		open(os.path.join('%s/run'%os.path.abspath(os.curdir),'monitor.pid'),'w').write("%s"%pid)
		main(conf)
