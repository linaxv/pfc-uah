import phonenumbers
from phonenumbers import geocoder
from phonenumbers.phonenumberutil import NumberParseException

from impacket import ImpactDecoder

import pcapy
from pcapy import open_offline, PcapError
from impacket.ImpactPacket import IP, TCP

import re
import logging


def find_ph_candidate0000(tcp):
	""" Search for 0x0000 and tries to find a phone candidate. Different OS's patterns are considered in offset """

	data_len = tcp.get_size() - tcp.get_header_size()
	wapp_packet = tcp.child()

	#fbyte0 = 0
	#sbyte0 = 0
	#ctrl_seq = 0x0000
	ph_candidate = ''

	for i in range(0,data_len):
		if (wapp_packet.get_byte(i) == 0x00) and (wapp_packet.get_byte(i+1) == 0x00):

			for offset in range(8,12):

				j = 0
				ph_candidate = ''
				start = i+offset
				byte = wapp_packet.get_byte(start+j)
				
				while ((byte >> 4) < 0xA):
					ph_candidate = ph_candidate + str(byte >> 4)

					if(0x0F & byte < 0xA):
						ph_candidate = ph_candidate + str(0x0F & byte)

					else:
						try:
							if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate, None))):
								return '+'+ph_candidate
							else:
								ph_candidate_aux = ph_candidate[:-1]

								while ph_candidate_aux is not '':
									if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate_aux, None))):
										return '+'+ph_candidate_aux
									ph_candidate_aux = ph_candidate_aux[:-1]
						except phonenumbers.phonenumberutil.NumberParseException as err:
							break
					
					j += 1;	byte = wapp_packet.get_byte(start+j)
				else:
					ph_candidate_aux = 'Not_initialized'
					try:
						if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate, None))):
							return '+'+ph_candidate
						else:
							ph_candidate_aux = ph_candidate[:-1]

							while ph_candidate_aux is not '':
								if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate_aux, None))):
									return '+'+ph_candidate_aux
								ph_candidate_aux = ph_candidate_aux[:-1]

					except phonenumbers.phonenumberutil.NumberParseException as err:
						pass
						#logging.error("[Parse]{%s} Failure in validating phone number (%s, aux:%s): %s", format(ctrl_seq, '02x'), ph_candidate,ph_candidate_aux, str(err))

	else:
		logging.error("[Parse]{0000} Error no User_id detected")
		ph_candidate = 'NO_USERID'
		return ph_candidate
def find_ph_candidate0000rev(tcp):
	""" Search for 0x0000 in reverse order and try to find a phone candidate. Different OS's patterns are considered in offset """

	data_len = tcp.get_size() - tcp.get_header_size()
	wapp_packet = tcp.child()

	#fbyte0 = 0
	#sbyte0 = 0
	#ctrl_seq = 0x0000
	ph_candidate = ''

	for i in range(data_len, -1, -1):
		#its never in the last one, so in order to avoid getting stucked at the end of the string
		i-=1
		if (wapp_packet.get_byte(i) == 0x00) and (wapp_packet.get_byte(i-1) == 0x00):
						
			for offset in range(8,12):
				
				j = 0
				ph_candidate = ''
				start = i+offset
				byte = wapp_packet.get_byte(start+j)
				
				while ((byte >> 4) < 0xA):
					ph_candidate = ph_candidate + str(byte >> 4)
					
					if(0x0F & byte < 0xA):
						ph_candidate = ph_candidate + str(0x0F & byte)

					else:
						try:
							if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate, None))):
								return '+'+ph_candidate
							else:
								ph_candidate_aux = ph_candidate[:-1]

								while ph_candidate_aux is not '':
									if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate_aux, None))):
										return '+'+ph_candidate_aux
									ph_candidate_aux = ph_candidate_aux[:-1]
						except phonenumbers.phonenumberutil.NumberParseException as err:
							break
					
					j += 1;	byte = wapp_packet.get_byte(start+j)
				else:
					ph_candidate_aux = 'Not_initialized'
					try:
						if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate, None))):
							return '+'+ph_candidate
						else:
							ph_candidate_aux = ph_candidate[:-1]

							while ph_candidate_aux is not '':
								if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate_aux, None))):
									return '+'+ph_candidate_aux
								ph_candidate_aux = ph_candidate_aux[:-1]

					except phonenumbers.phonenumberutil.NumberParseException as err:
						pass
						#logging.error("[Parse]{%s -rev} Failure in validating phone number (%s, aux:%s): %s", format(ctrl_seq, '02x'), ph_candidate,ph_candidate_aux, str(err))
	else:
		logging.error("[Parse]{0000rev} Error no User_id detected")
		ph_candidate = 'NO_USERID'
		return ph_candidate

def find_ph_candidate0000rev2(tcp):
	""" Search for 0x0000 in reverse order and try to find a phone candidate. Different OS's patterns are considered in offset """

	data_len = tcp.get_size() - tcp.get_header_size()
	wapp_packet = tcp.child()

	#ctrl_seq = 0x0000
	ph_candidate = ''
	#fbyte0 = 0
	#sbyte0 = 0

	for offset in range(8,12):
		fbyte0 = sbyte0 = 0
		for i in range(data_len, -1, -1):
			#its never in the last one, so in order to avoid getting stucked at the end of the string
			i-=1
			if (wapp_packet.get_byte(i) == 0x00) and (wapp_packet.get_byte(i-1) == 0x00):	
				j = 0
				ph_candidate = ''
				start = i+offset
				byte = wapp_packet.get_byte(start+j)
								
				while ((byte >> 4) < 0xA):
					ph_candidate = ph_candidate + str(byte >> 4)

					if(0x0F & byte < 0xA):
						ph_candidate = ph_candidate + str(0x0F & byte)
					else:
						try:
							if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate, None))):
								return '+'+ph_candidate
							else:
								ph_candidate_aux = ph_candidate[:-1]

								while ph_candidate_aux is not '':
									if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate_aux, None))):
										return '+'+ph_candidate_aux
									ph_candidate_aux = ph_candidate_aux[:-1]
						except phonenumbers.phonenumberutil.NumberParseException as err:
							break
					
					j += 1;	byte = wapp_packet.get_byte(start+j)
				else:
					ph_candidate_aux = 'Not_initialized'
					try:
						if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate, None))):
							return '+'+ph_candidate
						else:
							ph_candidate_aux = ph_candidate[:-1]

							while ph_candidate_aux is not '':
								if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate_aux, None))):
									return '+'+ph_candidate_aux
								ph_candidate_aux = ph_candidate_aux[:-1]

					except phonenumbers.phonenumberutil.NumberParseException as err:
						pass
						#logging.error("[Parse]{%s - rev2} Failure in validating phone number (%s, aux:%s): %s", format(ctrl_seq, '02x'), ph_candidate,ph_candidate_aux, str(err))
	else:
		logging.error("[Parse]{0000rev2} Error no User_id detected")
		ph_candidate = 'NO_USERID'
		return ph_candidate

def find_ph_candidateFF86(tcp):
	""" Search for 0xFF86 pattern in reverse order and try to find a phone candidate. All the OS's follow the same pattern """

	data_len = tcp.get_size() - tcp.get_header_size()
	wapp_packet = tcp.child()

	ctrl_seq = 0xFF86
	seq_pattern = 0
	ph_candidate = ''

	for i in range(data_len, -1, -1):
		if (wapp_packet.get_byte(i) == 0xFF) and (wapp_packet.get_byte(i+1) == 0x86):
					
			j = 0
			ph_candidate = ''
			start = i+2
			byte = wapp_packet.get_byte(start+j)
			
			while ((byte >> 4) < 0xA):
				ph_candidate = ph_candidate + str(byte >> 4)

				if(0x0F & byte < 0xA):
					ph_candidate = ph_candidate + str(0x0F & byte)

				else:
					try:
						if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate, None))):
							return '+'+ph_candidate
						else:
							ph_candidate_aux = ph_candidate[:-1]

							while ph_candidate_aux is not '':
								if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate_aux, None))):
									return '+'+ph_candidate_aux
								ph_candidate_aux = ph_candidate_aux[:-1]
					except phonenumbers.phonenumberutil.NumberParseException as err:
						break
				
				j += 1;	byte = wapp_packet.get_byte(start+j)
			else:
				ph_candidate_aux = 'Not_initialized'
				try:
					if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate, None))):
						return '+'+ph_candidate
					else:
						ph_candidate_aux = ph_candidate[:-1]

						while ph_candidate_aux is not '':
							if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate_aux, None))):
								return '+'+ph_candidate_aux
							ph_candidate_aux = ph_candidate_aux[:-1]

				except phonenumbers.phonenumberutil.NumberParseException as err:
					logging.error("[Parse]{%s} Failure in validating phone number (%s, aux:%s): %s", format(ctrl_seq, '02x'), ph_candidate,ph_candidate_aux, str(err))
	else:
		logging.error("[Parse]{FF86} Error no User_id detected")
		ph_candidate = 'NO_USERID'
		return ph_candidate

def find_ph_candidateCtrlSeq(tcp, ctrl_seq):
	""" Search for provided pattern in reverse order and try to find a phone candidate. All the OS's follow the same pattern """

	data_len = tcp.get_size() - tcp.get_header_size()
	wapp_packet = tcp.child()

	seq_pattern = 0
	ph_candidate = ''
	h_patt = ctrl_seq >> 8
	l_patt = 0xFF & ctrl_seq

	for i in range(data_len, -1, -1):
		if (wapp_packet.get_byte(i) == h_patt) and (wapp_packet.get_byte(i+1) == l_patt):
			
			j = 0
			ph_candidate = ''
			start = i+2
			byte = wapp_packet.get_byte(start+j)
			
			while ((byte >> 4) < 0xA):
				ph_candidate = ph_candidate + str(byte >> 4)

				if(0x0F & byte < 0xA):
					ph_candidate = ph_candidate + str(0x0F & byte)

				else:
					try:
						if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate, None))):
							return '+'+ph_candidate
						else:
							ph_candidate_aux = ph_candidate[:-1]

							while ph_candidate_aux is not '':
								if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate_aux, None))):
									return '+'+ph_candidate_aux
								ph_candidate_aux = ph_candidate_aux[:-1]

					except phonenumbers.phonenumberutil.NumberParseException as err:
						#logging.error("[Parse]{%s} Failure in validating phone number: %s", format(ctrl_seq, '02x'), str(err))
						break
				
				j += 1;	byte = wapp_packet.get_byte(start+j)
			else:
				ph_candidate_aux = 'Not_initialized'
				try:
					if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate, None))):
						return '+'+ph_candidate
					else:
						ph_candidate_aux = ph_candidate[:-1]

						while ph_candidate_aux is not '':
							if(phonenumbers.is_valid_number(phonenumbers.parse('+'+ ph_candidate_aux, None))):
								return '+'+ph_candidate_aux
							ph_candidate_aux = ph_candidate_aux[:-1]

				except phonenumbers.phonenumberutil.NumberParseException as err:
					logging.error("[Parse]{%s} Failure in validating phone number (%s, aux:%s): %s", format(ctrl_seq, '02x'), ph_candidate,ph_candidate_aux, str(err))
	else:
		logging.error("[Parse]{%s} Error no User_id detected", format(ctrl_seq, '02x'))
		ph_candidate = 'NO_USERID'
		return ph_candidate

def find_ph_candidateRegex(tcp):
	
	wapp_packet = tcp.child()

	try:
		#Fetching app_version and user_id
		regex = re.compile('^WA.*?([a-zA-Z\-\.0-9]+).*?([0-9]{6,})', re.DOTALL)
		#better to use search() than match()
		#check differences in case of doubts.
		tokens = regex.search(wapp_packet.get_buffer_as_string())
	except re.error as re_err:
		logging.error('[Regex {user_id}] Error while searching: %s',str(re_err))
	try:
		return '+'+tokens.group(2)

	except AttributeError as re_err:
		logging.error('[Regex {user_id}] Error no match: %s',str(re_err))
		return 'NO_USERID'