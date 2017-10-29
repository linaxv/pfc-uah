"Main program to do the chronology in user_id-IP by calling functions in utilities"

import __builtin__
__builtin__.flagPrivacy = 1
__builtin__.flagSP_testing = 0
__builtin__.flagES_testing = 0

import sys
import getopt

import logging
import time
import os

import dbfeed

# loging level to be called from command line with aliases
LOGGING_LEVELS = {'critical': logging.CRITICAL,
                  'error': logging.ERROR,
                  'warning': logging.WARNING,
                  'info': logging.INFO,
                  'debug': logging.DEBUG}


######### GLOBAL VARIABLES ###########

######### RECEIVE PARAMETERS #########

def main():

  priv_net = ''
  pcap_file = ''  
  logging_level = ''
  logging_file = ''
  working_dir = ''
  parser = ''
  
  try:
    myopts, args = getopt.gnu_getopt(sys.argv[1:],"",["pcap=","log=","debug-level=", "priv=", "parser=", "priv_net=", "wd=", "sp-testing=","es-testing="])

  except getopt.GetoptError as e:
    print(str(e))
    print("usage %s --pcap=pcap_file --log=LOGGING_FILE --debug-level=LOGGING_LEVEL [debug] --priv (/0/1) --parser=parser_code --priv_net=IP_network --wd=working_dir --sp-testing"% sys.argv[0])
    sys.exit(2)

  for o, a in myopts:
    if o == '--pcap':
      pcap_file=a
    if o == '--log':
      logging_file=a
    if o == '--debug-level':
      logging_level_str=a
      logging_level=LOGGING_LEVELS.get(a,logging.NOTSET)
    if o == '--priv':
      __builtin__.flagPrivacy = a
    if o == '--parser':
      parser = a
    if o == '--priv_net':
      priv_net = a
    if o == '--wd':
      working_dir = a
    if o == '--sp-testing':
      __builtin__.flagSP_testing = bool(int(a))
    if o == '--es-testing':
      __builtin__.flagES_testing = bool(int(a))


  ''' ##### SET DEFAULTS VALUES #####'''

  #default value INFO  
  
  if logging_level == '':
    logging_level_str="info"
    logging_level=logging.INFO

  #default value FF86
  
  if parser == '':
    parser = 'FF86'

  if priv_net == '':
    priv_net = '192.168.10.0/24'


  #Append date to logfile name

  timestr = time.strftime("%Y%m%d_%H%M%S")
  (shortname, ext) = os.path.splitext(logging_file)

  if ext is '':
    ext = '.log'
  logging_file = shortname + "_" + logging_level_str + '_' + timestr + ext

  logging_path = ''

  try:
    #Firstly, try to make dir provided
    if working_dir is not '':
      working_dir = working_dir + '/' + timestr
      #logging.debug("Creating working directory provided %s", working_dir)
      os.makedirs(working_dir)

      logging_path = working_dir + '/logs'
      #logging.debug("Creating logging directory in working directory provided %s", logging_path)
      os.makedirs(logging_path)
    else:
      #If not working directory provided, then work in pcap_file directory
      #logging.warning("No working directory provided. Creating directory structure in pcap path directory")
      working_dir = os.path.dirname(pcap_file) + '/execs/' + timestr
      os.makedirs(working_dir)

      logging_path = working_dir + '/logs'
      os.makedirs(logging_path)
  except OSError as err:
    #logging.error("Error while creating working directory: %s", str(err))
    print('Error while creating working directory: '+str(err))
    
    #logging.debug("Creating working directory in current working dir")
    working_dir = './' + timestr

    try:
      os.makedirs(working_dir)
      #logging_path = working_dir + '/logs'
      os.makedirs(logging_path)
    except OSError as err:
      #logging.error("Error while writing in current directory: %s", str(err))
      print('Error while writing in current directory: '+str(err))
      #logging.warning("No working directory created.")
      print('No working directory created.')

  logging_file = logging_path + '/' + logging_file
  
  #Config the level of debugging.
  logging.basicConfig(level=logging_level, filename=logging_file,
            format='%(asctime)s %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S', filemode='w')

  #Start loggin

  '''########## May start logging before and then move to the working directory ########## '''

  logging.info("Program started at %s", timestr)
  logging.info("Logging level set as '%s'", logging_level_str)

  if flagSP_testing is False:
    logging.info("State Packet parser testing set")

  ''' ############ May inform the parameters passed ??? ############'''

  ##### Feed State Table ######
  logging.debug("Call to 'processStateTraffic' function")
  if (dbfeed.processStateTraffic(pcap_file, priv_net, parser, working_dir)<0):sys.exit(1)
  logging.debug("Exit from 'processStateTraffic' function")

  ##### Count Volume #####  
  
  if flagSP_testing is False:
    logging.debug("Call to 'countVolumeDNS' function")
    if (dbfeed.countVolumeDNS(pcap_file, priv_net, working_dir)<0): sys.exit(1)
    logging.debug("Exit from 'countVolumeDNS' function")

if __name__ == "__main__":
  main()