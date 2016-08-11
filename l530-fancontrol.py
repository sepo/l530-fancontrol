#!/usr/bin/env python3
# vim: set fileencoding=UTF-8 :

"""
http://download.lenovo.com/ibmdl/pub/pc/pccbbs/mobiles/g3uj14us.txt

1 cpu 44°C (0xa8)
2 aps 38°C (0xa9)
3 crd 38°C (0xaa)
5 bat 60°C (0xac)
8 x7f 34°C (0xaf)
"""

import binascii
import re
import subprocess
import logging
import argparse
from time import sleep
import atexit
from signal import signal, SIGTERM, SIGINT, SIGUSR1

ec_sysfs_file = "/sys/kernel/debug/ec/ec0/io"

sensors = {
    'cpu': {
        'offset': 0xa8,
        'limits': {
                   55: 0,
                   60: 1,
                   70: 2,
                   80: 3,
                   85: 4,
                   90: 5
                   },
        'temp': 0,
        'afterburner': 15
    },
           
    'aps': {
        'offset': 0xa9,
        'limits': {
                   40: 0,
                   50: 1,
                   55: 2,
                   60: 3,
                   65: 4,
                   70: 5
                   },
        'temp': 0,
        'afterburner': 5
    },
           
    'crd': {
        'offset': 0xaa,
        'limits': {
                   40: 0,
                   50: 1,
                   55: 2,
                   60: 3,
                   65: 4,
                   70: 5
                   },
        'temp': 0,
        'afterburner': 5
    },
           
    'bat': {
        'offset': 0xac,
        'limits': {
                   69:  0,
                   74:  1,
                   79:  2,
                   84:  3,
                   89:  4,
                   94: 5
                   },
        'temp': 0,
        'afterburner': 5
    },
           
    'x7f': {
        'offset': 0xaf,
        'limits': {
                   40: 0,
                   50: 1,
                   55: 2,
                   60: 3,
                   65: 4,
                   70: 5
                   },
        'temp': 0,
        'afterburner': 5
    }
}

# Fan speeds from slow to fast starting at level 0
fan_speed_levels = [
                    0,      # level 0 (0xFF) fan is off
                    59,     # level 1 (0xC4)
                    97,     # level 2 (0xA9) BIOS 158 (0x9E)
                    119,    # level 3 (0x8C) BIOS 136 (0x88)
                    129,    # level 4 (0x7E)
                    255     # level 5 (0x00) fan runs at full speed
                    ]

supported_ecps = {
    '1.13': 'G3HT39WW',
    '1.14': 'G3HT40WW'
}

exit_event_registered = False

fan_mode_offset = 0x93
fan_mode_auto = 0x04
fan_mode_manual = 0x14

fan_speed_offset = 0x94

def int_to_byte(integer):
    return bytes([integer])

def int_to_byte_r(integer):
    i = 255 - integer
    return bytes([i])

def load_ec_module():
    with open('/proc/modules', 'r') as fh:
        for line in fh:
            if re.search('^ec_sys ', line) is not None:
                logging.debug('Kernel module "ec_sys" already loaded')
                return
    
    logging.debug('Loading kernel module "ec_sys" with write support enabled')
    result = subprocess.run(['modprobe', '-v', 'ec_sys', 'write_support=1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        logging.error('Loading kernel module "ec_sys" failed: {}'.format(result.stderr))
        quit()

def ec_read(offset = None):
    try:
        with open(ec_sysfs_file, 'rb', buffering=0) as fh:
            if offset == None:
                ec_data = fh.read()
            else:
                fh.seek(offset)
                fh.read(1)
    except FileNotFoundError:
        logging.error('Kernel module "ec_sys" is not loaded')
        quit()
    except Exception as e:
        logging.error("Failed reading from EC")
        logging.error(e)
        quit()
    return ec_data

def ec_write(offset, byte):
    if type(byte) == int:
        byte = int_to_byte(byte)
    elif type(byte) != bytes or len(byte) != 1:
        raise TypeError("only type bytes with an size of 1 is allowed here")
        
    try:
        with open(ec_sysfs_file, 'r+b', buffering=0) as fh:
            fh.seek(offset)
            fh.write(byte)
    except FileNotFoundError:
        logging.error("you have to load the ec_sys kernel module")
        quit()
    except Exception as e:
        logging.error("Failed writing to EC")
        logging.error(e)
        quit()

def invert(byte):
    return 255 - byte

def toggle_debug_logging(signum, stackframe):
    logger = logging.getLogger()
    loglevel = logger.getEffectiveLevel()
    if loglevel != logging.DEBUG:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    
def signal_handler(signum, stackframe):
    '''Just make sure we exit gracefully'''
    raise SystemExit

def install_exit_handler(exit_func):
    for signum in (SIGTERM, SIGINT):
        signal(signum, signal_handler)
    atexit.register(exit_func)
    
def install_toggle_debug_handler():
    signal(SIGUSR1, toggle_debug_logging)

def cleanup():
    logging.debug("Cleaning up")
    logging.debug("Setting fan mode to auto")
    ec_write(fan_mode_offset, fan_mode_auto)

# Command line arguments
parser = argparse.ArgumentParser(description='Controls the fan on Thinkpad L530.')
parser.add_argument("-v", "--verbose", help="enable verbose output",
                    action="store_true")
parser.add_argument("-d", "--debug", help="enable debug output",
                    action="store_true")
parser.add_argument("-f", "--foreground", help="do not detach from the console",
                    action="store_true")
parser.add_argument("-m", "--monitor", help="monitor the temperatures and regulates the fan speed",
                    action="store_true")
parser.add_argument("-i", "--interval", help="interval to check the EC",
                    action='store', type=int, default=5)
args = parser.parse_args()

# Setup logging
if args.verbose:
    loglevel=logging.INFO
elif args.debug:
    loglevel=logging.DEBUG
else:
    loglevel=logging.WARNING
    
loggging_format = '%(levelname)-8s %(message)s'
logging.basicConfig(format=loggging_format, level=loglevel)

logging.debug("Debug messages enabled")

install_toggle_debug_handler()


# Check root

load_ec_module()

ec_data = ec_read()

# verify ECP id and version
# Embedded Controller Program
# 1.14  (G3HT40WW)
#G3HT39WW(1.13) .
    
ecp_version_string = ec_data[0xf0:0xff].decode()
ecp_version_pattern = '(\w+)\(([\d\.]+)\)'
m = re.match(ecp_version_pattern, ecp_version_string)

try:
    ecp_id, ecp_version = m.groups()
except:
    logging.error("Could not get version of the ECP")
    quit()

if (ecp_version in supported_ecps
        and ecp_id == supported_ecps[ecp_version]):
    logging.info("ECP version {} ({}) is supported".format(ecp_version, ecp_id))
else:
    logging.error("The ECP version {} ({}) is not supported".format(ecp_version, ecp_id))
    quit()
    
temps = {}

while True:
    ec_data = ec_read()
            
    output = ""
    
    for sensor_name, sensor_data in sorted(sensors.items()):
        offset = sensor_data['offset']
        temp = ec_data[offset]
        try:
            temps[sensor_name]['temp'] = temp
        except KeyError:
            temps[sensor_name] = {'temp': temp}
        
        try:
            last_fan_level = temps[sensor_name]['fan_level']
        except KeyError:
            last_fan_level = 0
            
        last_fan_speed = fan_speed_levels[last_fan_level]
        
        afterburner = ""
        
        for temp_limit, fan_level in sorted(sensor_data['limits'].items()):
            if temp > temp_limit:
                continue
            
            if fan_speed_levels[fan_level] == 0 and last_fan_speed != 0:
                a = sensor_data['afterburner']
                if temp <= (temp_limit - a):
                    break
                else:
                    #logging.debug("activating afterburner for {} until reaching {}".format(sensor_name, ))
                    afterburner = ",*" + str(temp_limit - a)
            else:
                break
            
        temps[sensor_name]['fan_level'] = fan_level            
        output += "{}: {} ({}{}), ".format(sensor_name, temp, fan_level, afterburner)
    
    current_fan_mode = ec_data[fan_mode_offset]
    current_fan_speed = ec_data[fan_speed_offset]
    
    if args.monitor:
        
        fan_levels = [temps['fan_level'] for temps in temps.values()]
        
        # select only unique values and sort the list
        fan_levels = sorted(set(fan_levels),reverse = True)
        
        l = fan_levels[0]
        planned_fan_speed = fan_speed_levels[l]
        
        if current_fan_mode == fan_mode_auto:
            logging.debug("Setting fan mode to manual (current mode: auto)")
            ec_write(fan_mode_offset, fan_mode_manual)
            current_fan_mode = fan_mode_manual
        elif current_fan_mode == fan_mode_manual:
            logging.debug("Fan mode is already set to manual mode")
        else:
            logging.error("Wrong fan mode detected {}".format(current_fan_mode))
            quit()
        
        if not exit_event_registered:    
            install_exit_handler(cleanup)
            exit_event_registered = True
        
        if invert(current_fan_speed) != planned_fan_speed:
            planned_fan_speed = invert(planned_fan_speed)
            ec_write(fan_speed_offset, int_to_byte(planned_fan_speed))
            current_fan_speed = planned_fan_speed

    output += "fan_mode: {} ({}), ".format(current_fan_mode, hex(current_fan_mode))
    output += "fan_speed: {} ({})".format(current_fan_speed, hex(current_fan_speed))
        
    logging.info(output)
    
    sleep(args.interval)
