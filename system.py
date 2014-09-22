#!/usr/bin/env python
#coding:utf-8

import commands
import os
import base

class SystemStat(object):
	'系统基本性能数据收集'
	def __init__(self,interval = 30 , cpu_core = True ):
		self.interval = interval
		self.cpu_core = cpu_core

	def _read_cpu_usage(self):
		'''
		从/proc/stat 读取CPU状态
		返回值为列表: [ ['cpu', 'total_value','use_value'] , ['cpu0', 'total_value','use_value'], ...]
		'''
		ret = []
		lines = open("/proc/stat").readlines()
		for line in lines: 
			l = line.split() 
			if len(l) < 5: 
				continue 
			if l[0].strip().startswith('cpu'): 
				total = long(l[1]) + long(l[2]) + long(l[3]) + long(l[4]) + long(l[5]) + long(l[6]) + long(l[7])
				use = long(l[1]) + long(l[2]) + long(l[3])
				ret.append([l[0].strip(),total,use])
		return ret

	def get_cpu_usage(self):
		'''
		计算CPU使用率        
		返回值为字典:{'cpu':值 , 'cpu0':值 , ...} 默认返回值CPU总体使用率不包含各个核心使用率
		'''
		ret = {}
		stat1 = self._read_cpu_usage()
		base.time.sleep(self.interval)
		stat2 = self._read_cpu_usage()

		if not self.cpu_core:
			num = 1
		else:
			num = len(stat2)
		for i in range(num):
			cpuper = 100*((stat2[i][2] - stat1[i][2])/float(stat2[i][1] - stat1[i][1]))
			ret[stat2[i][0]]= int(cpuper)
			#print cpuper
		#for i in ret.keys():
			#print '%s 使用率: %s'%(i,ret[i])
		return ret

	def get_mem_usage(self):
		'''获取内存使用率,返回整数的百分数'''
		mem = {}
		meminfo = open("/proc/meminfo").readlines()
		for i in meminfo:
			if len(i) < 2:
				continue
			name = i.split(':')[0]
			value = i.split()[1]
			mem[name] = long(value) / 1024.0
		memper = (mem['MemTotal'] - mem['MemFree'] - mem['Buffers'] - mem['Cached'])/float(mem['MemTotal'])
		return int(100*memper)

	def _read_net_rate(self):
		'''计算网卡接收和发送的字节数
		返回值字典 {'网卡0':['接收字节','发送字节'],'网卡1':['接收字节','发送字节]}
		'''
		ret = {}
		netinfo = open('/proc/net/dev').readlines()
		for line in netinfo:
			line_split = line.split(':')
			if len(line_split) < 2:
				continue
			ret[line_split[0].strip()] = [line_split[1].split()[0]]
			ret[line_split[0].strip()].append(line_split[1].split()[8])
		#print 'netre:%s nettr:%s'%(netre,nettr)
		return ret

	def get_net_rate(self, interval = 2):
		'''获取网卡速率,返回值为字典{'网卡0':'速率','网卡1':'速率'} '''
		ret = {}
		total1 = {}
		total2 = {}
		netinfo = self._read_net_rate()
		for i in netinfo.keys():
			total1[i] = long(netinfo[i][0]) + long(netinfo[i][1])
		base.time.sleep(interval)
		netinfo = self._read_net_rate()
		for i in netinfo.keys():
			total2[i] = long(netinfo[i][0]) + long(netinfo[i][1])
		for i in total2.keys():
			ret[i] = ((total2[i] -total1[i])/1024.0/interval)*8
		return ret

	def get_load(self):
		''' 获取系统5分钟内的平均负载 '''
		return os.getloadavg()[0]

	def get_disk_usage(self):
		'''获取磁盘使用率,返回字典｛挂载点：百分数｝'''
		ret = {}
		mountinfo = open('/proc/mounts').readlines()
		for i in mountinfo:
			mountpoint = i.split()[1].strip()
			if i.split()[2].strip().startswith('ext'):
				mp_info = os.statvfs(mountpoint)
				mp_usage = 100*((mp_info.f_blocks - mp_info.f_bavail)/float(mp_info.f_blocks))
				ret[mountpoint] = int(mp_usage) 
		return ret

	def get_inode_usage(self):
		'''获取文件系统inode使用率,返回字典｛挂载点：百分数｝'''
		ret = {}
		mountinfo = open('/proc/mounts').readlines()
		for i in mountinfo:
			mountpoint = i.split()[1].strip()
			if i.split()[2].strip().startswith('ext'):
				inode_info = os.statvfs(mountpoint)
				inode_usage = 100*((inode_info.f_files - inode_info.f_favail)/float(inode_info.f_files))
				ret[mountpoint] = int(inode_usage)
		return ret

if __name__ == '__main__':
	test = SystemStat()
	print "CPU:%s"%test.get_cpu_usage()
	print "Mem:%s"%test.get_mem_usage()
	print "Disk:%s"%test.get_disk_usage()
	print "Inode:%s"%test.get_inode_usage()
	print "Net:%s"%test.get_net_rate()
	print "Load:%s"%test.get_load()