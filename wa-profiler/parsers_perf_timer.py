import parsers

from impacket import ImpactDecoder

import pcapy
from pcapy import open_offline, PcapError
from impacket.ImpactPacket import IP, TCP

import time

from texttable import Texttable

if __name__ == "__main__":

	max_times = 100
	t = Texttable()
	t_data = [['OS\Alg.','0000','0000rev','0000rev2','FF86']]
	#t_data = [['OS\Alg.','0000','0000rev2','FF86']]
	#t_data = [['OS\Alg.','0000rev2', 'FF86']]
	#t_data = [['OS\Alg.','0000rev']]

	try:
		pcapAnd = open_offline("../../caps/wa_Android_timer.pcap")
		pcapWP = open_offline("../../caps/wa_WP_timer.pcap")
		pcapIph = open_offline("../../caps/wa_iPhone_timer.pcap")

		pcaps = [pcapAnd, pcapIph, pcapWP]
		#pcaps = [pcapWP, pcapAnd]
		#pcaps = [pcapAnd]
		
		for pcap in pcaps:

			'''if pcap == pcapAnd:
				print "Android"
			if pcap == pcapIph:
				print "iPhone"
			if pcap == pcapWP:
				print "WindowsPhone"'''

			(hdr, data) = pcap.next()
			so_times = []

			while (hdr and data is not None ):
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

					###### bucles aqui de medida de tiempos por cada alg

					#print "Prueba 0000"
					counter0000 = 0
					#tcp = ip.child()

					for times in range(0, max_times):
						start = time.clock()
						if parsers.find_ph_candidate0000(tcp) == 'NO_USERID':
							print "Error in meassurements"
						end = time.clock()
						counter0000 = counter0000 + end - start

					m0000 = float(counter0000)/max_times
					so_times.append(m0000)
					
					#print "Prueba 0000rev"
					counter0000r = 0
					#tcp = ip.child()

					for times in range(0, max_times):
						tcp = ip.child()
						start = time.clock()
						if parsers.find_ph_candidate0000rev(tcp) == 'NO_USERID':
							print "Error in meassurements"
						end = time.clock()
						counter0000r = counter0000r + end - start

					m0000r = float(counter0000r)/max_times
					so_times.append(m0000r)


					#print "Prueba 0000rev2"
					counter0000r2 = 0
					#tcp = ip.child()

					for times in range(0, max_times):
						start = time.clock()
						if parsers.find_ph_candidate0000rev2(tcp) == 'NO_USERID':
							print "Error in meassurements"
						end = time.clock()
						counter0000r2 = counter0000r2 + end - start

					m0000r2 = float(counter0000r2)/max_times
					so_times.append(m0000r2)

					#print "Prueba FF86"
					counterFF86 = 0
					#tcp = ip.child()

					for times in range(0, max_times):
						start = time.clock()
						if parsers.find_ph_candidateFF86(tcp) == 'NO_USERID':
							print "Error in meassurements"
						end = time.clock()
						counterFF86 = counterFF86 + end - start

					mFF86 = float(counterFF86)/max_times
					so_times.append(mFF86)

					if pcap == pcapAnd:
						aux = ['Android']
						for i in range(0,len(so_times)):
							aux = aux + [so_times[i]]
						t_data.append(aux)
					if pcap == pcapIph:
						aux = ['iPhone']
						for i in range(0,len(so_times)):
							aux = aux+[so_times[i]]
						t_data.append(aux)
					if pcap == pcapWP:
						aux = ['WindowsPhone']
						for i in range(0,len(so_times)):
							aux = aux+[so_times[i]]
						t_data.append(aux)

					####Decode the following packet        

					(hdr, data) = pcap.next()
				except pcapy.PcapError as pcap_error:
					(hdr, data) = (None, None)
		t.set_precision(6)
		t.add_rows(t_data)
		print t.draw()
	except IOError as err:
		print('File error: '+str(err))