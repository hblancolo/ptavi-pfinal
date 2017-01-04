#!/usr/bin/python3
# -*- coding: utf-8 -*-
import socketserver
import sys
import os
import time
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaclient import XMLHandler


def event2log(event):
    event = (" ").join(event.split())  # cambio saltos de linea por espacios
    date = time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()))
    log_line = date + ' ' + event + '\n'
    with open(LOG_PATH, 'a') as log_file:
        log_file.write(log_line)


class EchoHandler(socketserver.DatagramRequestHandler):

    p_rtp_client = ['']  # almacena puerto rtp del cliente, para usarlo una vez
                         #  se recibe el ACK del cliente
    ip_client = ['']

    def handle(self):
        valid_request = False
        valid_method = False
        server_methods = ['INVITE', 'ACK', 'BYE']
        line_str = self.rfile.read().decode('utf-8')
        list_linecontent = line_str.split()
        method = list_linecontent[0]
        event2log(('Received from ' + self.client_address[0] + ':' +
                   str(self.client_address[1]) + ' ' + line_str))

#        self.json2registered()

        if len(list_linecontent) >= 3:  # checkea q la peticion es correcta
            valid_request = True
        else:
            self.wfile.write(b'SIP/2.0 400 Bad Request\r\n\r\n')
            event2log(('Sent to ' + self.client_address[0] + ':' +
                       str(self.client_address[1]) + ' ' +
                       'SIP/2.0 400 Bad Request\r\n\r\n'))

        if method in server_methods:  # checkea que el método sea válido
            valid_method = True
        else:
            self.wfile.write(b'SIP/2.0 405 Method Not Allowed\r\n\r\n')
            event2log(('Sent to ' + self.client_address[0] + ':' +
                       str(self.client_address[1]) + ' ' +
                       'SIP/2.0 405 Method Not Allowed\r\n\r\n'))

        if valid_method and valid_request:
            if method == 'INVITE':
                sdp_received = line_str.split('\r\n\r\n')[1]
                sdp_to_send = ('v=0\r\no=' + USER_NAME + ' ' + IP_UASERVER +
                               '\r\ns=misesion\r\nt=0\r\nm=audio ' +
                               str(PORT_RTP) + ' RTP')
                self.ip_client[0] = sdp_received.split('\r\n')[1].split(' ')[1]
                self.p_rtp_client[0] = sdp_received.split('\r\n')[4]
                self.p_rtp_client[0] = self.p_rtp_client[0].split(' ')[1]
                self.wfile.write(bytes('SIP/2.0 100 Trying\r\n\r\n'
                                       'SIP/2.0 180 Ring\r\n\r\n'
                                       'SIP/2.0 200 OK\r\n'
                                       'Content-Type: application/sdp\r\n\r\n'
                                       + sdp_to_send + '\r\n\r\n', 'utf-8'))
                event2log(('Sent to ' + self.client_address[0] + ':' +
                           str(self.client_address[1]) + ' ' +
                           'SIP/2.0 100 Trying\r\n\r\n'
                           'SIP/2.0 180 Ring\r\n\r\n'
                           'SIP/2.0 200 OK\r\n'
                           'Content-Type: application/sdp\r\n\r\n'
                           + sdp_to_send + '\r\n\r\n'))
            elif method == 'ACK':
                print('ACK received. Starting rtp transmission...')
                os.system('./mp32rtp -i ' + self.ip_client[0] + ' -p ' +
                          self.p_rtp_client[0] + ' < ' + fichero_audio)
                print('RTP transmission finished')
                event2log(('Sent to ' + self.ip_client[0] + ':' +
                           self.p_rtp_client[0] + ' ' + fichero_audio +
                           ' via RTP protocol'))
            elif method == 'BYE':
                self.wfile.write(b'SIP/2.0 200 OK\r\n\r\n')
                event2log(('Sent to ' + self.client_address[0] + ':' +
                           str(self.client_address[1]) + ' ' +
                           'SIP/2.0 200 OK\r\n\r\n'))

if __name__ == "__main__":
    try:
        CONFIG = sys.argv[1]
    except:
        sys.exit('Usage: python uaserver.py config')

    cHandler = XMLHandler()
    parser = make_parser()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))

    LOG_PATH = cHandler.datos_config[4][1]['path']
    event2log('Starting Server...')

    IP_PROXY = cHandler.datos_config[3][1]['ip']
    PORT_PROXY = int(cHandler.datos_config[3][1]['puerto'])
    USER_NAME = cHandler.datos_config[0][1]['username']
    IP_UASERVER = cHandler.datos_config[1][1]['ip']
    PORT_UASERVER = int(cHandler.datos_config[1][1]['puerto'])
    PORT_RTP = int(cHandler.datos_config[2][1]['puerto'])

    fichero_audio = cHandler.datos_config[5][1]['path']
    if not os.path.isfile(fichero_audio):
        sys.exit('File Error: ' + fichero_audio + ' does not exist')
        event2log(('Error: the file ' + fichero_audio + ' does not exist.'))

    print("Listening...")

    serv = socketserver.UDPServer((IP_UASERVER, PORT_UASERVER), EchoHandler)

    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print('Server Finished.')
