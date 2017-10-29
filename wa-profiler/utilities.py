# -*- coding: utf-8 -*-
"Tools to proccess captures, find WA packets, extract info from them, etc"

#+---------------------------------------------------------------------------+
'''Modules for the phone anonymizer function'''
#+---------------------------------------------------------------------------+
import phonenumbers
from phonenumbers import geocoder
from phonenumbers.phonenumberutil import NumberParseException
import hashlib

#+---------------------------------------------------------------------------+
'''Modules for the state packet parsing'''
#+---------------------------------------------------------------------------+

import re               							#needed for the regular expression
import parsers
from impacket import ImpactDecoder

#+---------------------------------------------------------------------------+
'''Modules for the logging and system feature'''
#+---------------------------------------------------------------------------+

import logging
import sys
#from sys import exit
import datetime

#+---------------------------------------------------------------------------+
'''Modules for the pcap_reader and pcap_filter'''
#+---------------------------------------------------------------------------+
import os
import pcapy
from pcapy import open_offline, PcapError
from impacket.ImpactPacket import IP, TCP

#+---------------------------------------------------------------------------+
'''Modules to parse DNS traffic'''
#+---------------------------------------------------------------------------+

import dpkt
import socket
import codecs
import netaddr

import dns.resolver
import dns.reversename

#+---------------------------------------------------------------------------+
'''Modules to make establish connection with ElasticSearch'''
#+---------------------------------------------------------------------------+

import requests
import json
from elasticsearch import Elasticsearch

from time import localtime, strftime

#+---------------------------------------------------------------------------+

'''Global variables'''

i_state = 1
i_volume = 1
events_dict_list = {}

#+---------------------------------------------------------------------------+

class UserStateEvent:
	"Stores wa_version, user_id (anonymized), timestamp (UNIX-epoch) and IP"
	def __init__(self, wa_version=None, osystem=None,anonym_user_id=None, timestamp=None, ip=None):
		self.wa_version = wa_version
		self.osystem = osystem
		self.anonym_user_id = anonym_user_id
		self.timestamp = timestamp
		self.user_ip = ip

class UserVolEvent:
	"Stores timestamp (UNIX-epoch) [us], src_IP, dst_IP, packet_size [bytes] (app point of view), protocol, port"
	def __init__(self, packet_size=None, proto=None, src_port=None, dst_port=None, timestamp=None, src_ip=None, dst_ip=None, wa_version=None, osystem=None, anonym_user_id=None):
		self.packet_size = packet_size
		self.proto = proto
		self.src_port = src_port
		self.dst_port = dst_port
		self.timestamp = timestamp
		self.src_ip = src_ip
		self.dst_ip = dst_ip
		### fields to fill when enriched information is added.
		self.wa_version = wa_version
		self.osystem = osystem
		self.anonym_user_id = anonym_user_id

class ESDown(Exception):
	def __init__(self,value):
		self.value = value
	def __str__(self):
		return repr(self.value)

def phone_anonymizer(phone): #return a phone number anonymized
	"Anonymizes a phone number in order to respect privacy in the PoC"

	#the phone number must have a '+' to be in E.164 format
	#in order to be parseable by phonenumbers
	if phone[0] is not '+':
		phone = str('+')+phone
	
	try:
		phone_number = phonenumbers.parse(phone, None)

		phone_format = phonenumbers.format_number(phone_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)

		phone_geo = str(geocoder.description_for_number(phone_number, "en"))

		if phone_geo is None: #idk if needed, just in case some city/country is not in the mapping table
			phone_geo = 'Unknown'

		tokens = phone_format.split()

		pre_anonym = ''
		for i in range(0,len(tokens)):
			pre_anonym = pre_anonym+str(tokens[i])+phone_geo

		###### hash of the recently generated string. I chose the less demanding algorithm, without collisions, in term of
		###### computing load among the supported ones ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
		hash_object = hashlib.sha224(pre_anonym)
		return hash_object.hexdigest()

	except NumberParseException as err:
		logging.warning('Error ocurred while processing in phone_anonymizer: %s', str(err))
def state_packet_parser(tcp, user_ip, pcap_hdr, parser): #Returns all the info in the state packet, receives a impacket object, IP, pcap_header, parser_selector
	"Extracts WA version, user_id (anonymized), timestamp (UNIX-epoch) and IP"

	try:
		regex = re.compile('^WA.*?([a-zA-Z0-9]+)([\-\.0-9]+)', re.DOTALL)
	except re.error as re_err:
		logging.error('[Regex {version}] Error while compiling: '+str(re_err))
		#by now, I think it's better to let the program go on

	try:
		#Fetching app_version
		tokens = regex.search(tcp.child().get_buffer_as_string())  #better to use search() than match()
		osystem = tokens.group(1)
		version = osystem+tokens.group(2)								#check differences in case of doubts.
	except re.error as re_err:
		logging.error('[Regex {version}] Error while searching: '+str(re_err))
		#by now, I think it's better to let the program go on

	""" CALL PARSERS"""

	ph_candidate = ''


	if flagSP_testing == 0 and parser is not 're':
		#exhaustive search process, trying first the most performant and probable.
		while True:#i know it's ugly, but it should only be executed once (i can't receive a value in the if condition and break is only for loops)
			ph_candidate = parsers.find_ph_candidateCtrlSeq(tcp, 0xFF06)
			if ph_candidate is not 'NO_USERID':break

			ph_candidate = parsers.find_ph_candidateCtrlSeq(tcp, 0xFF86)
			if ph_candidate is not 'NO_USERID':break

			ph_candidate = parsers.find_ph_candidate0000rev2(tcp)
			if ph_candidate is not 'NO_USERID':break

			ph_candidate = parsers.find_ph_candidate0000rev(tcp)
			if ph_candidate is not 'NO_USERID':break

			ph_candidate = parsers.find_ph_candidate0000(tcp)
			if ph_candidate is not 'NO_USERID':break
			
			if ph_candidate is 'NO_USERID':break
	else:
		if parser == '00':
			ph_candidate = parsers.find_ph_candidate0000(tcp)
		elif parser == '00rev':
			ph_candidate = parsers.find_ph_candidate0000rev(tcp)
		elif parser == '00rev2':
			ph_candidate = parsers.find_ph_candidate0000rev2(tcp)
		elif parser == 'ff86':
			ph_candidate = parsers.find_ph_candidateFF86(tcp)
		elif parser == 'ff06':
			ph_candidate = parsers.find_ph_candidateCtrlSeq(tcp, 0xFF06)
		elif parser == 're':
			ph_candidate = parsers.find_ph_candidateRegex(tcp)
		else:
			ph_candidate = parsers.find_ph_candidate0000(tcp)


	''' ANONYMIZE PHONE'''

	user_id = ph_candidate
	anonym_user_id = phone_anonymizer(user_id)

	######## Uncomment when wanna see results in stdout ########

	#print "\n\tS.O. and WhatsApp version:\t\t %s" %version
	logging.info("[Parse] Android version: %s", version)
	
	if int(flagPrivacy) == 1:
		logging.info("[Parse] Phone identified %s", anonym_user_id)
		#print "\tWhatsApp user_id:\t\t\t flagPrivacy set on"
	else:
		logging.info("[Parse] Phone identified %s - %s", user_id, anonym_user_id)
		#print "\tWhatsApp user_id:\t\t\t %s" %user_id
	
	#print "\tOperative System:\t\t\t %s" %osystem
	#print "\tWhatsApp anonym_id:\t\t\t %s" %anonym_user_id

	try:
		timestamp_sec = pcap_hdr.getts()[0]
		timestamp_usec = pcap_hdr.getts()[1]
		timestamp = float(timestamp_sec + float(timestamp_usec)/1000000)

	except Exception as e:
		logging.error("[Header] Failed getting timestamp from header. Exception: %s" %str(e))

	logging.debug("[Parse]{frame time} %s", datetime.datetime.fromtimestamp(timestamp_sec).strftime('%Y-%m-%d %H:%M:%S'))

	#print "\tTimestamp (UNIX-epoch) of packet:\t %f" %timestamp

	user_state = UserStateEvent(version, osystem, anonym_user_id, timestamp, user_ip)
	return user_state

def pcap_filter(pcap_f, filter_str, key_str):
	"Filters a pcap file with a filter provided and renames the file with a key string provided"
	#pcap_filtered_file = ''
	pcap_file = pcap_f
	
	try:
		#open not-processed file
		pcap = open_offline(pcap_file)

		try:
			#Set filter to only catch desired traffic
			pcap.setfilter(filter_str)
		except PcapError, e:
			print ('Error while setting filter: '+str(e))
			logging.error("Error while setting filter: %s", str(e))
			pass

		#write to disc (Renaming filtered file + create dumper)
		(shortname, ext) = os.path.splitext(pcap_file)
		pcap_filtered_file = shortname + '_filtered'+ key_str + ext

		try:
			dumper = pcap.dump_open(pcap_filtered_file)
		except pcapy.PcapError as pcap_error:
			logging.error("[Filter] Error while opening dumper for filtered file: %s", str(pcap_error))
			print "[Filter] Error while opening dumper for filtered file: "+str(pcap_error)

		#process packet
		def filterPacket(hdr, data):
			dumper.dump(hdr,data)

		#call to user callback with the whole .pcap file
		packet_limit = -1

		try:
			pcap.loop(packet_limit,filterPacket)
		except pcapy.PcapError as pcap_error:
			logging.error("[Filter] Error while looping filtered file: %s. Exiting...", str(pcap_error))
			print "[Filter] Error while looping for filtered file: "+str(pcap_error + ". Exiting...")
			sys.exit(1)

		logging.debug("[Filter] Filtered filename: %s.",pcap_filtered_file)

	except IOError as err:
		print('File error: '+str(err)+'. Exiting')
		logging.error("File error: %s. Exiting", str(err))
		sys.exit(1)

	dumper = None
	return pcap_filtered_file

def pcap_reader(pcap_file, state_already, parser=None, priv_net=None):
	"Looks for WA traffic (user and control) in a pcap file"

	if flagSP_testing == 1: printChosenParser(parser)

	nouser_counter = 0
	flagAlreadyPaused = 0

	#lists to store signalization traffic info
	wa_state_list = []
	wa_state_vol_list = []

	#list to store volume traffic info
	wa_vol_list = []

	#Regex to check if it is control traffic
	st_packet_re = re.compile("^WA.*(Android|iPhone|WP)")

	try:
		#Create a 'Reader' Object

		pcap = open_offline(pcap_file)

		#Decode the first packet        

		(hdr, data) = pcap.next()

		while (hdr and data is not None):
			try:

				#figure out wich datalink type

				datalink = pcap.datalink()

				if datalink == pcapy.DLT_EN10MB:
				    decoder = ImpactDecoder.EthDecoder()
				elif datalink == pcapy.DLT_LINUX_SLL:
				    decoder = ImpactDecoder.LinuxSLLDecoder()

				#start decoding
				layer2 = decoder.decode(data)

				#Dissect layers

				#IP
				ip = layer2.child()
				ipsrc = ip.get_ip_src()

				#TCP
				tcp = ip.child()
				dport = tcp.get_th_dport()

				#WA
				wapp =  tcp.child()
				
				#figure out if it's control packet or volume packet
				
				if st_packet_re.search(wapp.get_buffer_as_string()):
					if state_already == 0:
						if dport == 443 and tcp.get_size() > 0:
						    pkt_info = 'SSL'
						elif (dport == 5222 or dport == 5223) and tcp.get_size() > 0:
						    pkt_info = ('XMPP')

						logging.info('[Parse] Es un paquete de estado de WhatsApp: %s', pkt_info)


						#Receives an UserStateEvent object
						
						wa_user_info = state_packet_parser(tcp, ipsrc, hdr, parser)

						#Check if parser_method is correctly chosen

						if wa_user_info.anonym_user_id is None:
							nouser_counter = nouser_counter + 1

						if nouser_counter > 2 and flagAlreadyPaused == 0:
							print "Too many user ids not identified. May the parsing method is not correctly chosen according to the StatePacket Version."
							answer = raw_input("Do you really want to continue? (y/n): ")

							if answer is "y":
								flagAlreadyPaused = 1
							elif answer is "n":
								print("Exiting program")
								logging.critical("Too many user id not identified. Exiting program...")
								sys.exit(1)
							else:
								#if any other caracter is pressed, I let the program turn another packet.
								pass

						#Append last info
						wa_state_list.append(wa_user_info)

						#create volume-class object and append it

						wa_state_vol_info = vol_packet_parser(ip,hdr,priv_net)
						wa_state_vol_list.append(wa_state_vol_info)

				else:
					#process here for only volume packets
					if priv_net:
						wa_vol_info = vol_packet_parser(ip,hdr,priv_net)
						wa_vol_list.append(wa_vol_info)

				####Decode the following packet        

				(hdr, data) = pcap.next()
			except pcapy.PcapError as pcap_error:
				logging.debug("[Loop] .pcap file end %s", str(pcap_error))
				(hdr, data) = (None, None)
	except IOError as err:
		print('[Pcap-parser] File error: '+str(err))
		logging.error("[Pcap-parser] File error: %s", str(err))
		sys.exit(1)
		
	return (wa_state_list, wa_state_vol_list, wa_vol_list)

def vol_packet_parser(ip, pcap_hdr, priv_net=None):

	#IP 
	ipsrc = ip.get_ip_src()
	ipdst = ip.get_ip_dst()

	#TCP
	tcp = ip.child()
	dport = tcp.get_th_dport()
	sport = tcp.get_th_sport()

	#get proto in a not very clean way... I'll see if it's enough

	proto = ''

	if priv_net:
		priv_net = IPNetworkConverter(priv_net)
		ip_set = netaddr.IPSet([priv_net])

		#Try to know sense of packet.
		if ipdst in ip_set: #incoming
			if sport == 80:
				proto = 'HTTP'
			elif sport == 443:
				proto = 'SSL/TLS'
			elif sport == 5222 or sport == 5223:
				proto = 'XMPP'
		else:#outcoming
			if dport == 80:
				proto = 'HTTP'
			elif dport == 443:
				proto = 'SSL/TLS'
			elif dport == 5222 or dport == 5223:
				proto = 'XMPP'

	#get size

	data_len = tcp.get_size() - tcp.get_header_size()

	#Get timestamp

	timestamp = 0

	try:
		timestamp_sec = pcap_hdr.getts()[0]
		timestamp_usec = pcap_hdr.getts()[1]
		timestamp = float(timestamp_sec + float(timestamp_usec)/1000000)

	except Exception as e:
		logging.error("[Volume Packet Parser]{Header} Failed getting timestamp from header. Exception: %s" %str(e))

	logging.debug("[Volume Packet Parser]{frame time} %s", datetime.datetime.fromtimestamp(timestamp_sec).strftime('%Y-%m-%d %H:%M:%S'))

	vol_info = UserVolEvent(data_len, proto, sport, dport, timestamp, ipsrc, ipdst)

	return vol_info

def setDB_setProps_state(host,port,index_name,type_name):
	''' Creates Elasticsearch index and type and sets fields type and format. ''' 
	es = Elasticsearch([{'host': str(host), 'port': int(port)}])

	#mapping_time = '{"mappings":{"' + str(type_name) + '":{"time":{"enabled":"true"},"properties":{"time":{"type":"date","format":"yyyy/MM/dd HH:mm:ss"}}}}}'
	#mapping_ip ='{"mappings":{"' + str(type_name) + '":{"properties":{"ip_addr":{"type":"ip"}}}}}'
	mappings = '{"mappings":{"' + str(type_name) + '":{"properties":{"src_ip_addr":{"type":"ip"},"time":{"type":"date","format":"yyyy/MM/dd HH:mm:ss"}}}}}'


	es.indices.create(index=str(index_name), ignore=[], body=mappings)
	#es.indices.create(index=str(index_name), ignore=[], body=mapping_ip)
	#es.indices.put_mapping(index=str(index_name), doc_type=str(type_name), ignore=400, body=mapping_time)
	global i_state
	i_state = 1

def setDB_setProps_vol(host,port,index_name,type_name):
	''' Creates Elasticsearch index and type and sets fields type and format. ''' 
	es = Elasticsearch([{'host': str(host), 'port': int(port)}])

	#mapping_time = '{"mappings":{"' + str(type_name) + '":{"time":{"enabled":"true"},"properties":{"time":{"type":"date","format":"yyyy/MM/dd HH:mm:ss"}}}}}'
	#mapping_ip ='{"mappings":{"' + str(type_name) + '":{"properties":{"src_ip_addr":{"type":"ip"},"dst_ip_addr":{"type":"ip"}}}}}'

	#mappings = '{"mappings":{"' + str(type_name) + '":{"properties":{"time":{"type":"date","format":"yyyy/MM/dd HH:mm:ss"},"src_ip_addr":{"type":"ip"},"dst_ip_addr":{"type":"ip"},"packet-size":{"type":"integer"}}}}}'
	mappings = '{"properties":{"time":{"type":"date","format":"yyyy/MM/dd HH:mm:ss"},"src_ip_addr":{"type":"ip"},"dst_ip_addr":{"type":"ip"},"packet-size":{"type":"integer"}}}'
	#es.indices.create(index=str(index_name), ignore=400, body=mapping_ip)
	#es.indices.put_mapping(index=str(index_name), doc_type=str(type_name), ignore=400, body=mapping_time)
	
	#JSON DEBBUGGED, I CAN AFFORD ignore=[]
	#I assume the index is already created
	es.indices.put_mapping(index=str(index_name), doc_type=str(type_name), ignore=[], body=mappings)
	global i_volume
	i_volume = 1

def insert2DB(host,port,index_name,type_name,entries):
	''' Inserts data into Elasticsearch DB. Data is passed through entries (JSON-formatted)'''
	es = Elasticsearch([{'host': str(host), 'port': int(port)}])

	i = 0
	global i_state
	global i_volume

	#Intro code
	if i_state == 1:
		i = i_state
	else:
		i = i_volume
	
	'''#Append data already indexed (specialy important in 'volume-packet' _type)

	i = es.count(index=str(index_name), doc_type=str(type_name))['count'] + 1
	print i'''

	i_print = i + 4


	#Start to index according _id calculated
	for entry in entries:
		es.index(index=str(index_name), doc_type=str(type_name), id=i, body=json.loads(entry))
		i = i +1
		if i == i_print:
			print entry
	
	#Exit code
	if i_state == 1:
		i_state = i
	else:
		i_volume = i

def createJSON_statePacket(state_list):
	''' Creates JSON-formatted string list with valuable data in State-packets'''
	entries = []

	for state in state_list:
		#entries.append('{"src_ip_addr":"' + str(state.user_ip) + '","time":"' + strftime("%Y/%m/%d %H:%M:%S", localtime(int(state.timestamp))) + '","os":"' + str(state.osystem) + '","wa-version":"' + str(state.wa_version) + '","id-anon":"' + str(state.anonym_user_id) +'"}')
		entries.append('{"src_ip_addr":"' + str(state.user_ip) + '","src_ip_addr_text":"' + str(state.user_ip) + '","time":"' + strftime("%Y/%m/%d %H:%M:%S", localtime(int(state.timestamp))) + '","os":"' + str(state.osystem) + '","wa-version":"' + str(state.wa_version) + '","id-anon-state":"' + str(state.anonym_user_id) +'"}')
	return entries


def createJSON_volPacket(vol_list,sense,traffic_type):
	''' Creates JSON-formatted string list with valuable data in Vol-packets'''

	entries = []

	for vol_info in vol_list:
		#entries.append('{"src_ip_addr":"' + str(vol_info.src_ip) + '","dst_ip_addr":"' + str(vol_info.dst_ip) + '","time":"' + strftime("%Y/%m/%d %H:%M:%S", localtime(int(vol_info.timestamp))) + '","dst_port":"' + str(vol_info.dst_port) + '","protocol":"' + str(vol_info.proto) + '","packet-size":"' + int(vol_info.packet_size) +'"}')
		entries.append('{"src_ip_addr":"' + str(vol_info.src_ip) + '","src_ip_addr_text":"' + str(vol_info.src_ip) + '","dst_ip_addr":"' + str(vol_info.dst_ip) + '","dst_ip_addr_text":"' + str(vol_info.dst_ip) + '","time":"' + strftime("%Y/%m/%d %H:%M:%S", localtime(int(vol_info.timestamp))) + '","src_port":"' + str(vol_info.src_port) + '","dst_port":"' + str(vol_info.dst_port) + '","protocol":"' + str(vol_info.proto) + '","packet-size":"' + str(vol_info.packet_size) +'","sense":"' + str(sense)+ '","traffic_type":"'+str(traffic_type)+'","id-anon":"'+str(vol_info.anonym_user_id)+'","os":"'+str(vol_info.osystem)+'","wa-version":"'+str(vol_info.wa_version)+'"}')
	return entries

def checkExistingESindex(host,port, index):
	''' Checks if index already exists and if so, remove it '''
	es = Elasticsearch([{'host': str(host), 'port': int(port)}])

	if es.indices.exists(index):
		es.indices.delete(index=index)

def checkESDB(host,port):
	''' Checks if Elasticsearch DB is up'''
	res = requests.get('http://' + str(host) + ':' + str(port))

	if res.status_code != 200:
		print "Error: ES DB not reacheable"
		raise ESDown("Error: Elasticsearch DB not reacheable")

def extractStateEvents(wa_state_list):
	"Extracts changes in StateEvents. Example: a user changes his IP" 
	global events_dict_list
	events_dict_list = {}

	for state in wa_state_list:
		if state.user_ip not in events_dict_list:
			events_dict_list[state.user_ip] = [{'timestamp':state.timestamp, 'id-anon':state.anonym_user_id, 'wa-version':state.wa_version, 'os':state.osystem}]
		elif events_dict_list[state.user_ip][-1]['wa-version'] != state.wa_version or events_dict_list[state.user_ip][-1]['os'] != state.osystem or events_dict_list[state.user_ip][-1]['id-anon'] != state.anonym_user_id:
			events_dict_list[state.user_ip].append({'timestamp':state.timestamp, 'id-anon':state.anonym_user_id, 'wa-version':state.wa_version, 'os':state.osystem})
		else:
			pass

def enrichVolume(wa_vol_list, sense):
	"Enriches volume information with wa-user data such as id-anon, wa-version and os"

	global events_dict_list

	#print events_dict_list

	if wa_vol_list:
		if sense == 'incoming':
			#loop to enrich IN volume
			for vol_info in wa_vol_list:
				try:

					#first try with the most recent event.
					if vol_info.timestamp >= events_dict_list[vol_info.dst_ip][-1]['timestamp']:
						vol_info.wa_version = events_dict_list[vol_info.dst_ip][-1]['wa-version']
						vol_info.osystem = events_dict_list[vol_info.dst_ip][-1]['os']
						vol_info.anonym_user_id = events_dict_list[vol_info.dst_ip][-1]['id-anon']
					else:
						#loop to detect event
						for i, event in enumerate(events_dict_list[vol_info.dst_ip]):
							if vol_info.timestamp >= event['timestamp'] and vol_info.timestamp < events_dict_list[vol_info.dst_ip][i+1]['timestamp']:
								vol_info.wa_version = event['wa-version']
								vol_info.osystem = event['os']
								vol_info.anonym_user_id = event['id-anon']
								break
					#if id-anon not assigned yet, set the first one
					if vol_info.anonym_user_id is None:
						vol_info.wa_version = events_dict_list[vol_info.dst_ip][0]['wa-version']
						vol_info.osystem = events_dict_list[vol_info.dst_ip][0]['os']
						vol_info.anonym_user_id = events_dict_list[vol_info.dst_ip][0]['id-anon']
				except:
					print("[countVolumeDNS]{enrichVolume} Error while retrieving State changes information (volume IN). IP:" +vol_info.dst_ip)
					logging.warning("[countVolumeDNS]{enrichVolume} Error while retrieving State changes information (volume IN). %s", vol_info.dst_ip)
					pass
		elif sense == 'outcoming':
			#loop to enrich OUT volume
			for vol_info in wa_vol_list:
				try:
					#first try with the most recent event.
					if vol_info.timestamp >= events_dict_list[vol_info.src_ip][-1]['timestamp']:
						vol_info.wa_version = events_dict_list[vol_info.src_ip][-1]['wa-version']
						vol_info.osystem = events_dict_list[vol_info.src_ip][-1]['os']
						vol_info.anonym_user_id = events_dict_list[vol_info.src_ip][-1]['id-anon']
					else:
						#loop to detect event
						for i, event in enumerate(events_dict_list[vol_info.src_ip]):
							if vol_info.timestamp >= event['timestamp'] and vol_info.timestamp < events_dict_list[vol_info.src_ip][i+1]['timestamp']:
								vol_info.wa_version = event['wa-version']
								vol_info.osystem = event['os']
								vol_info.anonym_user_id = event['id-anon']
								break
					#if id-anon not assigned yet, set the first one
					if vol_info.anonym_user_id is None:
						vol_info.wa_version = events_dict_list[vol_info.src_ip][0]['wa-version']
						vol_info.osystem = events_dict_list[vol_info.src_ip][0]['os']
						vol_info.anonym_user_id = events_dict_list[vol_info.src_ip][0]['id-anon']
				except:
					print("[countVolumeDNS]{enrichVolume} Error while retrieving State changes information (volume OUT). IP:"+vol_info.src_ip)
					logging.warning("[countVolumeDNS]{enrichVolume} Error while retrieving State changes information (volume OUT). %s", vol_info.src_ip)
					pass


		return wa_vol_list
	else:
		print "[countVolumeDNS]{enrichVolume} Critical error: no volume information provided. Exiting program..."
		logging.critical("[countVolumeDNS]{enrichVolume} Critical error: no volume information provided. Exiting program...")
		exit(-1)




def WAIPgetterDNSresponses(pcapDNS_file):
	"Gets whatsapp IP from DNS response. Returns uniques IP and net /24 lists"

	try:
		with codecs.open(pcapDNS_file, 'rb') as pcapDNS:
			pcapDNS = dpkt.pcap.Reader(pcapDNS)

			ip_net_list = []
			ip_list = []

			for ts, raw_pkt in pcapDNS:
				if pcapDNS.datalink() == dpkt.pcap.DLT_LINUX_SLL: #Frame is not Eth
					eth = dpkt.sll.SLL(raw_pkt)
				else:
					eth = dpkt.ethernet.Ethernet(raw_pkt)
				ip = eth.data
				udp = ip.data
				# make the dns object out of the udp data and check for it being a RR (answer)
				# and for opcode QUERY (I know, counter-intuitive)
				#Check before if is actually a DNS packet
				if udp.dport != 53 and udp.sport != 53: continue
				
				try:
					dns = dpkt.dns.DNS(udp.data)
				except dpkt.dpkt.UnpackError as err:
					print('Error while parsing DNS:'+str(err))
					logging.error("[WA-IP DNS responses]Error while parsing DNS: %s,"+str(err))
					continue

				#Check if is Query/response
				if dns.qr != dpkt.dns.DNS_R: continue

				#Check if is standard query
				if dns.opcode != dpkt.dns.DNS_QUERY: continue

				#Check if there is no errors.
				if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: continue 
				if len(dns.an) < 1: continue
				
				for answer in dns.an:
					if answer.type == dpkt.dns.DNS_A and "whatsapp" in answer.name:# and answer not in ip_net_list:
						answer_ip_net = str(netaddr.IPNetwork(socket.inet_ntoa(answer.rdata)+'/24').network)+'/24'
						answer_ip = str(socket.inet_ntoa(answer.rdata))

						if answer_ip_net not in ip_net_list:
							ip_net_list.append(answer_ip_net)
						if answer_ip not in ip_list:
							ip_list.append(answer_ip)

	except IOError as err:
		print('File error: '+str(err))
		logging.error("[WA-IP DNS responses]File error: %s,"+str(err))

	return (ip_net_list,ip_list)

def WAIPgetterInTraffic(pcap_IN_file,WA_nets_out):
	"Gets IP from WhatsApp incoming traffic"
	ip_net_list_in = WA_nets_out
	try:
		with codecs.open(pcap_IN_file, 'rb') as pcap_IN:
			pcap_IN = dpkt.pcap.Reader(pcap_IN)

			print "WA_nets_out from DNS"
			print WA_nets_out

			for ts, raw_pkt in pcap_IN:
				if pcap_IN.datalink() == dpkt.pcap.DLT_LINUX_SLL: #Frame is not Eth
					eth = dpkt.sll.SLL(raw_pkt)
				else:
					eth = dpkt.ethernet.Ethernet(raw_pkt)
				ip = eth.data
				IP = str(netaddr.IPNetwork(socket.inet_ntoa(ip.src)+'/24').network)+'/24'
				#print IP
				if IP in WA_nets_out:
					#Consider IP into 
					#tcp = ip.data
					if IP not in ip_net_list_in:
						ip_net_list_in.append(IP)
				else:
					#print "Not in DNS response"
					pass
					#print "TCP data from WhatsApp"
				'''elif IP no:
					#Make a DNS ANY Query and check if is there
					#if so, insert into DB
					pass
				else:
					#Make a WHOIS query and check if is there
					#if so, insert into DB
					#may update DEscr list? pased by reference?? from countVolume???
					print "Not in DNS response"
					pass'''
	

	except IOError as err:
		print('File error: '+str(err))

def WAIPgetterInTrafficv2(pcap_IN_file,WA_nets_DNS, WA_DNS):
	"Gets IP from WhatsApp incoming traffic"
	ip_net_list_in = WA_nets_DNS
	ip_list_in = WA_DNS
	try:
		with codecs.open(pcap_IN_file, 'rb') as pcap_IN:
			pcap_IN = dpkt.pcap.Reader(pcap_IN)

			print "WA_nets from DNS"
			print WA_nets_DNS
			print len(WA_nets_out)

			for ts, raw_pkt in pcap_IN:
				if pcap_IN.datalink() == dpkt.pcap.DLT_LINUX_SLL: #Frame is not Eth
					eth = dpkt.sll.SLL(raw_pkt)
				else:
					eth = dpkt.ethernet.Ethernet(raw_pkt)
				ip = eth.data
				IP_WA = socket.inet_ntoa(ip.src)
				IP_net = str(netaddr.IPNetwork(IP_WA+'/24').network)+'/24'
				#print IP
				if IP_net in ip_net_list_in: #Asi unicamente me estoy tragando IP contiguas de otras aplicaciones como FB, instagram, masquerade, etc. Aqui es donde
											#deberia hacer una rDNS	-->  HECHO
					if IP_WA not in ip_list_in:
						rname = dns.reversename.from_address(str(IP_WA))
						rDNS = str(dns.resolver.query(rname,"PTR")[0])

						if 'whatsapp' in rDNS:
							ip_list_in.append(IP_WA)
				else:
					#print "Not in DNS response"
					pass
					#print "TCP data from WhatsApp"
				'''elif IP no:
					#Make a DNS ANY Query and check if is there
					#if so, insert into DB
					pass
				else:
					#Make a WHOIS query and check if is there
					#if so, insert into DB
					#may update DEscr list? pased by reference?? from countVolume???
					print "Not in DNS response"
					pass'''
	

	except IOError as err:
		print('File error: '+str(err))

def WAIPgetterInTrafficv3(pcap_IN_file,WA_nets_DNS, WA_DNS):
	"Gets IP from WhatsApp incoming traffic"
	ip_net_list_in = WA_nets_DNS
	ip_list_in = WA_DNS
	try:
		with codecs.open(pcap_IN_file, 'rb') as pcap_IN:
			pcap_IN = dpkt.pcap.Reader(pcap_IN)

			#print "WA_nets from DNS"
			#print WA_nets_DNS
			#print len(WA_nets_out)

			for ts, raw_pkt in pcap_IN:
				if pcap_IN.datalink() == dpkt.pcap.DLT_LINUX_SLL: #Frame is not Eth
					eth = dpkt.sll.SLL(raw_pkt)
				else:
					eth = dpkt.ethernet.Ethernet(raw_pkt)
				ip = eth.data
				IP_WA = str(socket.inet_ntoa(ip.src))
				#IP_net = str(netaddr.IPNetwork(IP_WA+'/24').network)+'/24'
				#print IP
				#if IP_net in ip_net_list_in:
				if IP_WA not in ip_list_in:
					rname = dns.reversename.from_address(IP_WA)
					rDNS = str(dns.resolver.query(rname,"PTR")[0])
					#set try: except in case of time out rDNS dns.exception.Timeout

					if 'whatsapp' in rDNS:
						ip_list_in.append(IP_WA)
					elif 'sl-reverse' in rDNS:
						ip_list_in.append(IP_WA)
					else:
						pass
				#else:
				#	pass
				'''elif IP no:
					#Make a DNS ANY Query and check if is there
					#if so, insert into DB
					pass
				else:
					#Make a WHOIS query and check if is there
					#if so, insert into DB
					#may update DEscr list? pased by reference?? from countVolume???
					print "Not in DNS response"
					pass'''
	

	except IOError as err:
		print('File error: '+str(err))
	
	return (ip_net_list_in, ip_list_in)

def strFilterNets(ip_list, sense):

	vol_filter = '('+sense + ' net '

	c = 0
	top = len(ip_list) - 1

	for net in ip_list:
		if c < top: # and net not in vol_filter:
			vol_filter = vol_filter + net + ' or ' + sense + ' net '
		elif c >= top:
			vol_filter = vol_filter + net + ')'
		c = c + 1

	return vol_filter

def strFilterHosts(ip_list, sense):
	''' Creates filter string with already uniques IPs '''

	vol_filter = '('+ sense + ' host '

	c = 0
	top = len(ip_list) - 1

	for host in ip_list:
		if c < top:
			vol_filter = vol_filter + host + ' or ' + sense + ' host '
		elif c >= top:
			vol_filter = vol_filter + host + ')'
		c = c + 1

	return vol_filter

def IPNetworkConverter(ip_str):
	"Converts IP into network IP if not in /## format"
	
	regexIP = re.compile('\/\d{1,2}', re.DOTALL)
	result = regexIP.search(ip_str)

	if result is not None:
		return ip_str
	else:
		ip_str = ip_str+'/24' 
		logging.debug("Private IP network converted %s", ip_str)
		return ip_str

def isIPAddress(ip_str):
	try:
		netaddr.IPNetwork(str(ip_str))
		return 1
	except netaddr.AddrFormatError as err:
		print('Private network definition error: '+str(err))
		logging.error("'Private network definition error: %s",str(err))
		return -1

def printChosenParser(parser):
	"Print into debug file the parsing mode chosen"

	parsing_method = ''

	if parser == '00':
		parsing_method = '00 sequence control finder'
	elif parser == '00rev':
		parsing_method = '00 sequence control finder reverse mode'
	elif parser == '00rev2':
		parsing_method = '00 sequence control finder reverse mode optimized'
	elif parser == 'ff86':
		parsing_method = 'FF86 sequence control finder'
	elif parser == 'ff06':
		parsing_method = 'FF06 sequence control finder'
	elif parser == 're':
		parsing_method = 'Regex defined. Old State-packet version. Before Nov 2015.'
	else:
		parsing_method = '00 sequence control finder'

	print("Parsing method: "+parsing_method)
	logging.info("[State-Packet]{Parser} Parsing method: %s", parsing_method)
