"Module including DB Feed functions to feed: State table, volume table,"

import utilities
from utilities import ESDown

import os
import subprocess
import logging

import sys

def processStateTraffic(pcap_filename,priv_net, parser, wd):
	"Extracts WA control info and stores it in DB"

	#Old filters
	#state_filter = 'src net ' + priv_net + ' and (tcp port 443 or tcp port 5222) and tcp[0x20] = 0x57 and tcp[0x21] = 0x41'
	#state_filter = 'src net ' + priv_net + ' and (tcp port 443 or tcp port 5222)'
	
	logging.debug("processStateTraffic function started")

	#Filter file. 1st set command.
	if utilities.isIPAddress(priv_net) > 0:
		logging.debug("Private IP network provided %s", priv_net)
		priv_net = utilities.IPNetworkConverter(priv_net)

		(shortname, ext) = os.path.splitext(pcap_filename)
		pcap_out_filename = shortname + '_filtered'+ 'WA_state' + ext

		cmd_filter = "ngrep -I " + pcap_filename + " -O " + pcap_out_filename + " -x WA 'src net " + priv_net + " and (tcp port 5222 or tcp port 443)'"
		logging.debug("Filter state traffic command:\t%s", cmd_filter)
	else:
		print "No State Info analysed. Not supported IP network format provided. Exiting program..."
		logging.critical("No State Info analysed. Not supported IP network format provided. Exiting program...")
		return -1

	#Filter file. 2nd run command.
	try:
		output = subprocess.check_output(cmd_filter, shell=True)
	except OSError as err:
		print ("Error while creating subprocess to filter WA State traffic"+str(err))
		logging.critical("Error while creating subprocess to filter WA State traffic: %s",str(err))
		return -1

	#Filter file. 3rd check output file.
	try:
		if os.path.getsize(pcap_out_filename) > 0:
			logging.debug("State file output filtered created successfully.")
		else:
			logging.critical("State file output filtered not created. Nothing filtered or filesystem problem.")
			return -1
	except OSError as err:
		print ("Error while checking file size WA State traffic"+str(err))
		logging.error("Error while checking file size WA State traffic: %s",str(err))
		pass

	#Filter file. 4th move output file to working directory.

	pcapSTATE = ''
	state_dir = wd + '/stateInfo'

	try:
		os.makedirs(state_dir)
		pcapSTATE = state_dir + '/' + os.path.basename(pcap_out_filename)
		os.rename(pcap_out_filename, pcapSTATE)

	except OSError as err:
		print('Error while creating "State" directory: '+str(err))
		logging.error("Error while creating 'State' directory: %s",str(err))
		pass

	#Parse file to obtain StatePackets and volume info

	(wa_state_list, wa_state_vol_list, rubish) = utilities.pcap_reader(pcapSTATE, 0, parser, priv_net)

	##call here function to extract State changes

	utilities.extractStateEvents(wa_state_list)

	#result of the previous function stored in moduled-global variable (utilities module) in order to prevent copies of the list between funtions
	##call here to enrich volume state info.

	wa_state_vol_enriched_list = utilities.enrichVolume(wa_state_vol_list, 'outcoming')

	if flagES_testing is False:
		storeStatePackets2DB(wa_state_list, wa_state_vol_enriched_list)
		
	logging.debug("[processStateTraffic] Just before return")
	return 1 #it is mandatory to return something because on the other side i'm checking the value

def countVolume(pcap_filename, priv_net):
	"Filters WA traffic volume and stores it in database"


	''' #### First of all outcoming traffic ####'''

	(pcapOUT, ip_WA_nets) = getPcapOutTraffic(pcap_filename)
	#just in case I make a deeper proccessing
	pcapOutWA = pcapOUT

	''' ### Now, incoming traffic: from general to particular ### '''
	#Filter by dst priv_net provided

	(pcapIN, ip_WA_netsInOut) = getPcapInTraffic(pcap_filename, priv_net, ip_WA_nets)

def getPcapOutTraffic(pcap_filename):
	"Filters outcoming traffic and returns the pcap_file"

	#Filter DNS traffic
	pcap_IN_f = utilities.pcap_filter(pcap_filename, "udp port 53", "WA_DNS")

	#Get WhatsApp IP's nets from DNS responses:

	ip_WA_nets = utilities.WAIPgetterDNSresponses(pcap_IN_f)

	#Create an outcoming file

	out_vol_filter = utilities.strFilterNets(ip_WA_nets, 'dst')
	out_vol_filter = out_vol_filter + ' and (tcp port 443 or tcp port 5222)'
	
	pcapOUT_f = utilities.pcap_filter(pcap_filename, out_vol_filter, "WA_TCP_out")

	return (pcapOUT_f,ip_WA_nets)

def getPcapInTraffic(pcap_filename, priv_net, ip_WA_DNS_nets):
	"Filters incoming traffic coarsely and returns pcap_file"
	#Check priv address

	if utilities.isIPAddress(priv_net) > 0:
		#Filter by dst priv_net:
		in_vol_filter_net = 'dst net ' + priv_net + ' and (tcp port 443 or tcp port 5222)'
		pcapIN_f_coarse = utilities.pcap_filter(pcap_filename, in_vol_filter_net, "WA_TCP_in_coarse")

		#Try to get IP's from WhatsApp in the previous file (adding them to the list obtained in DNS responses)
		ip_netsInOut = utilities.WAIPgetterInTraffic(pcapIN_f_coarse, ip_WA_DNS_nets)

		#Create an incoming file by filtering with the new list

		in_vol_filter = utilities.strFilterNets(ip_netsInOut, 'src')
		pcapIN_f = utilities.pcap_filter(pcapIN_f_coarse, in_vol_filter, "WA_TCP_in")
		
		return (pcapIN_f, ip_netsInOut)
	else:
		print "No incoming traffic analysed"
		#log into debug file
		return

def countVolumeInOut(pcap_filename, priv_net):
	"Filters WA traffic volume and stores it in database"

	''' ### Incoming traffic: from general to particular ### '''
	''' #### First of all incoming traffic with DNS IP's as seed ####'''
	#Genereal view: Filter by dst priv_net provided

	#Filter DNS traffic
	if utilities.isIPAddress(priv_net) > 0:

		priv_net = utilities.IPNetworkConverter(priv_net)

		dns_filter = 'udp port 53'
		pcap_f_DNS = utilities.pcap_filter(pcap_filename, dns_filter, "WA_DNSv2")
		
		#Get WhatsApp IP's nets from DNS responses:
		(ip_WA_nets, ip_WA) = utilities.WAIPgetterDNSresponses(pcap_f_DNS)

		#print "Hasta aqui sin errores"

		(pcapIN, ip_WA_netsInOut, ip_WA_InOut) = getPcapInTrafficv2(pcap_filename, priv_net, ip_WA_nets, ip_WA)


		''' ### Now, outcoming traffic ### '''

		pcapOUT = getPcapOutTrafficv2(pcap_filename, ip_WA_InOut)
	else:
		print "No incoming traffic analysed"
		#log into debug file
		return

def getPcapOutTrafficv2(pcap_filename, IP_WA):
	"Filters outcoming traffic and returns the pcap_file"

	#Filter DNS traffic

	#pcap_IN_f = utilities.pcap_filter(pcap_filename, "udp port 53", "WA_DNS")

	#Get WhatsApp IP's nets from DNS responses:

	#ip_WA_nets = utilities.WAIPgetterDNSresponses(pcap_IN_f)

	#Create an outcoming file

	out_vol_filter = utilities.strFilterNets(IP_WA, 'dst')
	out_vol_filter = out_vol_filter + ' and (tcp port 443 or tcp port 5222)'
	
	pcapOUT_f = utilities.pcap_filter(pcap_filename, out_vol_filter, "WA_TCP_outv2")

	return (pcapOUT_f)

def getPcapInTrafficv2(pcap_filename, priv_net, ip_WA_nets, ip_WA):
	"Filters incoming traffic coarsely and returns pcap_file"
	#Check priv address

	if utilities.isIPAddress(priv_net) > 0:
		#Filter by dst priv_net:
		in_vol_filter_net = 'dst net ' + priv_net + ' and (tcp port 443 or tcp port 5222)'
		pcapIN_f_coarse = utilities.pcap_filter(pcap_filename, in_vol_filter_net, "WA_TCP_in_coarsev2")

		#Try to get IP's from WhatsApp in the previous file (adding them to the list obtained in DNS responses)
		(ip_netsInOut, ip_InOut) = utilities.WAIPgetterInTrafficv2(pcapIN_f_coarse, ip_WA_nets, ip_WA)
		print ip_InOut
		print len(ip_InOut)

		#Create an incoming file by filtering with the new list of IP's /32

		in_vol_filter = utilities.strFilterNets(ip_InOut, 'src')
		pcapIN_f = utilities.pcap_filter(pcapIN_f_coarse, in_vol_filter, "WA_TCP_inv2")
		
		return (pcapIN_f, ip_netsInOut, ip_InOut)
	else:
		print "No incoming traffic analysed"
		#log into debug file
		return
def countVolumeInOutv3(pcap_filename, priv_net):
	"Filters WA traffic volume and stores it in database"

	''' ### Incoming traffic: from general to particular ### '''
	''' #### First of all incoming traffic with DNS IP's as seed ####'''
	#Genereal view: Filter by dst priv_net provided

	#Filter DNS traffic
	if utilities.isIPAddress(priv_net) > 0:

		priv_net = utilities.IPNetworkConverter(priv_net)

		dns_filter = 'udp port 53'
		pcap_f_DNS = utilities.pcap_filter(pcap_filename, dns_filter, "WA_DNSv3")
		
		#Get WhatsApp IP's nets from DNS responses:
		(ip_WA_nets, ip_WA) = utilities.WAIPgetterDNSresponses(pcap_f_DNS)

		#print "Hasta aqui sin errores"

		(pcapIN, ip_WA_netsInOut, ip_WA_InOut) = getPcapInTrafficv3(pcap_filename, priv_net, ip_WA_nets, ip_WA)


		''' ### Now, outcoming traffic ### '''

		pcapOUT = getPcapOutTrafficv3(pcap_filename, ip_WA_InOut)
	else:
		print "No incoming traffic analysed"
		#log into debug file
		return

def getPcapOutTrafficv3(pcap_filename, IP_WA):
	"Filters outcoming traffic and returns the pcap_file"

	#Filter DNS traffic

	#pcap_IN_f = utilities.pcap_filter(pcap_filename, "udp port 53", "WA_DNS")

	#Get WhatsApp IP's nets from DNS responses:

	#ip_WA_nets = utilities.WAIPgetterDNSresponses(pcap_IN_f)

	#Create an outcoming file

	out_vol_filter = utilities.strFilterNets(IP_WA, 'dst')
	out_vol_filter = out_vol_filter + ' and (tcp port 443 or tcp port 5222)'
	
	pcapOUT_f = utilities.pcap_filter(pcap_filename, out_vol_filter, "WA_TCP_outv3")

	return (pcapOUT_f)

def getPcapInTrafficv3(pcap_filename, priv_net, ip_WA_nets, ip_WA):
	"Filters incoming traffic coarsely and returns pcap_file"
	#Check priv address

	if utilities.isIPAddress(priv_net) > 0:
		#Filter by dst priv_net:
		in_vol_filter_net = 'dst net ' + priv_net + ' and (tcp port 443 or tcp port 5222)'
		pcapIN_f_coarse = utilities.pcap_filter(pcap_filename, in_vol_filter_net, "WA_TCP_in_coarsev3")

		#Try to get IP's from WhatsApp in the previous file (adding them to the list obtained in DNS responses)
		(ip_netsInOut, ip_InOut) = utilities.WAIPgetterInTrafficv3(pcapIN_f_coarse, ip_WA_nets, ip_WA)
		print ip_InOut
		print len(ip_InOut)

		#Create an incoming file by filtering with the new list of IP's /32

		in_vol_filter = utilities.strFilterNets(ip_InOut, 'src')
		pcapIN_f = utilities.pcap_filter(pcapIN_f_coarse, in_vol_filter, "WA_TCP_inv3")
		
		return (pcapIN_f, ip_netsInOut, ip_InOut)
	else:
		print "No incoming traffic analysed"
		#log into debug file
		return

def countVolumeDNS(pcap_filename, priv_net, wd):
	"Filters WA traffic volume and stores it in database"

	'''
	Get WA Ip's from DNS queries/answers and then filters by sense: in/out by these IP's ip.src == "IP" / ip.dst == "IP"
	Then, filters by sense: in/out
	'''
	
	#incoming: Filter by dst priv_net provided
	#outcoming: Filter by dst priv_net provided

	#Filter DNS traffic
	if utilities.isIPAddress(priv_net) > 0:
		logging.debug("Private IP network provided %s", priv_net)
		priv_net = utilities.IPNetworkConverter(priv_net)

		#if I filter with the dst network, I improve performance
		
		dns_filter = 'dst net ' + priv_net + ' and udp port 53'
		
		logging.debug("Filtering DNS file with filter: %s", dns_filter)
		
		pcap_f_DNS = utilities.pcap_filter(pcap_filename, dns_filter, "WA_DNS_dns")

		#check if file has no empty size
		if os.path.getsize(pcap_f_DNS) > 24: #size of an empty pcap
			logging.debug("DNS output filtered created successfully.")
		else:
			logging.critical("[countVolumeDNS] No DNS traffic found. Pcap file is empty.")
			print "[countVolumeDNS] No DNS traffic found. Pcap file is empty."
			return -1
		
		logging.debug("Pcap file with DNS traffic %s", pcap_f_DNS)
		
		#Get WhatsApp IP's nets from DNS responses:
		(ip_WA_nets, ip_WA) = utilities.WAIPgetterDNSresponses(pcap_f_DNS)

		pcapIN = getPcapInTrafficDNS(pcap_filename, ip_WA)

		logging.debug("Pcap file with incoming traffic %s", pcapIN)


		''' ### Now, outcoming traffic ### '''

		pcapOUT = getPcapOutTrafficDNS(pcap_filename, ip_WA)

		logging.debug("Pcap file with outcoming traffic %s", pcapOUT)


		## Create directory with method name and move files

		volume_dir = wd + '/only_DNS'

		new_pcapOUT = ''
		new_pcapIN = ''
		new_pcapDNS = ''

		try:
			os.makedirs(volume_dir)

			new_pcapOUT = volume_dir + '/' + os.path.basename(pcapOUT)
			new_pcapIN = volume_dir + '/' + os.path.basename(pcapIN)
			new_pcapDNS = volume_dir + '/' + os.path.basename(pcap_f_DNS)

		except OSError as err:
			logging.error('Error while creating "Volume" directory: %s. Exiting...', str(err))
			print('Error while creating "Volume" directory: '+str(err)+'. Exiting...')
			pass

		try:
			os.rename(pcapOUT, new_pcapOUT)
			os.rename(pcapIN, new_pcapIN)
			os.rename(pcap_f_DNS, new_pcapDNS)

		except OSError as err:
			logging.error('Error while moving pcap files: %s. Exiting...', str(err))
			print('Error while moving pcap files: '+str(err)+'. Exiting...')
			pass

		#return (new_pcapOUT, new_pcapIN)

		''' Storing important info in DB '''

		#call to pcap_reader to get important information

		(rubish1, rubish2, wa_volume_list_IN) = utilities.pcap_reader(new_pcapIN, 1, 'parser' ,priv_net)
		(rubish1, rubish2, wa_volume_list_OUT) = utilities.pcap_reader(new_pcapOUT,1, 'parser',priv_net)

		#print len(wa_volume_list_IN)
		#print len(wa_volume_list_OUT)

		#call here to enrich volume information with StatePacket info

		wa_vol_enriched_list_IN = utilities.enrichVolume(wa_volume_list_IN, 'incoming')
		wa_vol_enriched_list_OUT = utilities.enrichVolume(wa_volume_list_OUT, 'outcoming')

		#try to store the info in the DB

		if flagES_testing is False:
			logging.debug("[countVolumeDNS]{Insert into DB} About to enter into Volume2DB")
			#storeVolumePackets2DB(wa_volume_list_OUT, wa_volume_list_IN)
			storeVolumePackets2DB(wa_vol_enriched_list_IN, wa_vol_enriched_list_OUT)

	else:
		print "No incoming traffic analysed. Not supported IP network format provided. Exiting program..."
		logging.critical("No incoming traffic analysed. Not supported IP network format provided. Exiting program...")
		return -1

	return 1

def storeStatePackets2DB(wa_state_list, wa_state_vol_list):

	host = 'localhost'
	port = 9200
	

	index_name = 'wa-profiler_new-mapping'
	traffic_type = 'control_data'
	sense = 'outcoming'

	try:
		utilities.checkESDB(host,port)

		#check if Index exists before and remove it
		utilities.checkExistingESindex(host,port,index_name)

		if wa_state_list or wa_state_vol_list:
			type_name_state = 'state-packet'

			#set properties before (data types)
			utilities.setDB_setProps_state(host,port,index_name,type_name_state)
			#create JSON wa-state
			json_state = utilities.createJSON_statePacket(wa_state_list)
			#call here to include data in DB
			utilities.insert2DB(host,port, index_name,type_name_state,json_state)

			### volume
			#type_name_vol = 'volume-state-packet'
			type_name_vol = 'volume-packet'
			#set properties before (data types)
			utilities.setDB_setProps_vol(host,port,index_name,type_name_vol)
			#create JSON wa-state-vol
			json_state_vol = utilities.createJSON_volPacket(wa_state_vol_list,sense,traffic_type)
			#call here to include data in DB
			utilities.insert2DB(host,port,index_name,type_name_vol,json_state_vol)			
		else:
			logging.error("[processStateTraffic]{Insert into DB} May be one or more empty list")
			print "[processStateTraffic]{Insert into DB} May be one or more empty list"
	except ESDown as err:
		print("[processStateTraffic] Error, EslasticSearch DB is down: %s", str(err))
		logging.critical("[processStateTraffic] EslasticSearch DB is down: %s", str(err))
		sys.exit(1)



def storeVolumePackets2DB(volume_list_IN, volume_list_OUT):

	host = 'localhost'
	port = 9200
	#index_name = 'wa-profiler'

	index_name = 'wa-profiler_new-mapping'
	traffic_type = 'user_data'

	try:
		utilities.checkESDB(host,port)

		if volume_list_OUT:
			#type_name = 'volume-packet-out'
			type_name = 'volume-packet'
			sense = 'outcoming'

			#set properties before (data types)
			#utilities.setDB_setProps_vol(host,port,index_name,type_name) 
			#create JSON vol-out
			#json_vol_out = utilities.createJSON_volPacket(volume_list_OUT)
			json_vol_out = utilities.createJSON_volPacket(volume_list_OUT,sense,traffic_type)
			#print len(json_vol_out)
			#call here to include data in DB
			utilities.insert2DB(host,port,index_name,type_name,json_vol_out)

		if volume_list_IN:
			#type_name = 'volume-packet-in'
			type_name = 'volume-packet'
			sense = 'incoming'

			#set properties before (data types)
			#utilities.setDB_setProps_vol(host,port,index_name,type_name)
			#create JSON vol-in
			#json_vol_in = utilities.createJSON_volPacket(volume_list_IN)
			json_vol_in = utilities.createJSON_volPacket(volume_list_IN,sense,traffic_type)
			#print len(json_vol_in)
			#call here to include data in DB
			utilities.insert2DB(host,port, index_name,type_name,json_vol_in)

	except ESDown as err:
		print("[processStateTraffic] Error, ElasticSearch DB is down: %s", str(err))
		logging.critical("[processStateTraffic] ElasticSearch DB is down: %s", str(err))
		sys.exit(1)

def getPcapOutTrafficDNS(pcap_filename, IP_WA):
	"Filters outcoming traffic and returns the pcap_file"

	#Create an outcoming file

	out_vol_filter = utilities.strFilterHosts(IP_WA, 'dst')
	out_vol_filter = out_vol_filter + ' and (tcp port 443 or tcp port 5222)'
	
	pcapOUT_f = utilities.pcap_filter(pcap_filename, out_vol_filter, "WA_DNS_tcp_xmpp_out")

	return (pcapOUT_f)

def getPcapInTrafficDNS(pcap_filename, IP_WA):
	"Filters incoming traffic coarsely and returns pcap_file"

	#Create an incoming file by filtering with the new list of IP's /32

	in_vol_filter = utilities.strFilterHosts(IP_WA, 'src')
	in_vol_filter = in_vol_filter + ' and (tcp port 443 or tcp port 5222)'

	pcapIN_f = utilities.pcap_filter(pcap_filename, in_vol_filter, "WA_DNS_tcp_xmpp_in")
	
	return (pcapIN_f)