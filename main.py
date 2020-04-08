import pycurl
import pyshark
from urllib.parse import urlencode

# includes for pyinstaller
from py._vendored_packages import iniconfig
from pyshark import config
from py import _path


# POST data to website
def push_to_website(state, stitches = None, current_design=None, total_designs=None):
    url = "http://himzo.sch.bme.hu/api/machine/status"
    c = pycurl.Curl()

    c.setopt(c.URL, url)
    if stitches is None:
        data = {'state': state, 'machine_key': 'XXXXXXX'}
    else:
        data = {'state': state, 'machine_key': 'XXXXXXX', 'stitches': stitches, 'designs': total_designs, 'current_design': current_design}
    pf = urlencode(data)

    c.setopt(c.POSTFIELDS, pf)
    c.setopt(c.SSL_VERIFYPEER, 0)
    c.setopt(c.SSL_VERIFYHOST, 0)
    c.perform()
    c.close()
    return


def send_dst_to_website():
    url = "http://himzo.sch.bme.hu/api/machine/dst"
    c = pycurl.Curl()

    c.setopt(c.URL, url)
    c.setopt(c.POST, 1)
    c.setopt(c.HTTPPOST, [('machine_key', 'XXXXXXX'), ('dst', (c.FORM_FILE, 'random.dst', c.FORM_FILENAME, 'random.dst'))])
    c.setopt(c.SSL_VERIFYPEER, 0)
    c.setopt(c.SSL_VERIFYHOST, 0)
    c.perform()
    c.close()


# bitmagic
def process_data(data, c_stitches=None, current_design=None, total_designs=None):

    if c_stitches is not None:
        print("Running")
        push_to_website(1, c_stitches, current_design, total_designs)

    # check if machine is running
    if data[7] == 68 and data[8] == 68:
        print("Running")
        push_to_website(1)
    elif data[7] == 68 and data[8] == 70:
        print("End")
        push_to_website(0)
    elif data[7] == 83:
        if data[8] == 69:
            print("Machine error")
            push_to_website(2)
        elif data[8] == 77:
            print("End")
            push_to_website(3)
        elif data[8] == 78:
            print("Stop switch")
            push_to_website(4)
        elif data[8] == 83:
            print("Needle stop")
            push_to_website(5)
        elif data[8] == 84:
            print("Thread break")
            push_to_website(6)


def check_for_dst(data):
    return data[len(data)-7] == "54" and data[len(data)-8] == "53" and data[len(data)-9] == "44" and data[8] == "48"


def check_for_end_of_packet(data):
    return data[len(data)-1] == "00" and data[len(data)-2] == "0d" and data[len(data)-3] == "03"


def check_for_start(data):
    for i in range(2, len(data)-1):
        if data[i] == "83" and data[i-1] == "00" and data[i-2] == "00":
            return i


cap = pyshark.LiveCapture(None, bpf_filter='tcp port 7891')
img_data = []
dst_data = []
image_set = False
dst_incoming = False
first_packet = False
for packet in cap.sniff_continuously():
    if packet[1].src == '192.168.1.100' and hasattr(packet.tcp, 'payload'):
        payload = packet.tcp.payload.split(':')
        if dst_incoming:
            if first_packet:
                payload = payload[12:]
                first_packet = False
            if check_for_end_of_packet(payload):
                payload = payload[:len(payload)-3]
            for i in range(0, len(payload)):
                if i+2 < len(payload)-1 and payload[i] == "00" and payload[i+1] == "00" and payload[i+2] == "f3":
                    dst_data.append("0000f31a")
                    dst_incoming = False
                    first_packet = False
                    break
                dst_data.append(payload[i])

    if packet[1].src == '192.168.1.202' and hasattr(packet.tcp, 'payload'):
        payload = packet.tcp.payload.split(':')
        payload_dec = []
        for hex_number in payload:
            payload_dec.append(int(hex_number, 16))

        if len(payload) == 21:
            designs = int(payload[10])
            current_design = int(payload[12])+1

            print("Total designs: ", designs, "Current design: ", current_design)
            stitches = int(payload[16] + payload[15], 16)-1024
            process_data(payload_dec, stitches, current_design, designs)
        else:
            process_data(payload_dec)
        if check_for_dst(payload):
            dst_incoming = True
            first_packet = True
        elif "".join(payload) == "553e554d0a0050505200000000590d00":
            dst_incoming = True
            first_packet = True
        elif not dst_incoming:
            first_packet = False
            dst_incoming = False
        else:
            dst_data = dst_data[1:]
            dst_data = bytes.fromhex("".join(dst_data))
            with open("random.dst", 'wb') as output:
                output.write(dst_data)
                output.close()
            send_dst_to_website()
            dst_data = []
            first_packet = False
            dst_incoming = False

