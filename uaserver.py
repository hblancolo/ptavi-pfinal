#!/usr/bin/python3
# -*- coding: utf-8 -*-
import socketserver
import sys
import os
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaclient import XMLHandler


class EchoHandler(socketserver.DatagramRequestHandler):

    p_rtp_client = [''] # almacena puerto rtp del cliente, para usarlo una vez se recibe el ACK del cliente
    ip_client = ['']

    def handle(self):
        valid_request = False
        valid_method = False
        server_methods = ['INVITE', 'ACK', 'BYE']
        line_str = self.rfile.read().decode('utf-8')
        list_linecontent = line_str.split()
        method = list_linecontent[0]
#        self.json2registered()

        if len(list_linecontent) >= 3:  # checkea q la peticion es correcta
            valid_request = True
        else:
            self.wfile.write(b'SIP/2.0 400 Bad Request\r\n\r\n')

        if method in server_methods: # checkea que el método sea válido
            valid_method = True
        else:
            self.wfile.write(b'SIP/2.0 405 Method Not Allowed\r\n\r\n')

        if valid_method and valid_request:
            if method == 'INVITE':
                body_sdp = line_str.split('\r\n\r\n')[1] # me quedo con el sdp
                self.ip_client[0] = body_sdp.split('\r\n')[1].split(' ')[1]
                self.p_rtp_client[0] = body_sdp.split('\r\n')[4].split(' ')[1]
                self.wfile.write(bytes('SIP/2.0 100 Trying\r\n\r\n'
                                       'SIP/2.0 180 Ring\r\n\r\n'
                                       'SIP/2.0 200 OK\r\n\r\n' + body_sdp + 
                                       '\r\n\r\n', 'utf-8'))
            elif method == 'ACK':
                print('ACK received. Starting rtp transmission...')
                os.system('./mp32rtp -i ' + self.ip_client[0] + ' -p ' + 
                          self.p_rtp_client[0] + ' < ' + fichero_audio)
            elif method == 'BYE':
                self.wfile.write(b'SIP/2.0 200 OK\r\n\r\n')

if __name__ == "__main__":
    try:
        CONFIG = sys.argv[1]
    except:
        sys.exit('Usage: python uaserver.py config')

    cHandler = XMLHandler()
    parser = make_parser()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))

    IP_PROXY = cHandler.datos_config[3][1]['ip']
    PORT_PROXY = int(cHandler.datos_config[3][1]['puerto'])
    USER_NAME = cHandler.datos_config[0][1]['username']
    IP_UASERVER = cHandler.datos_config[1][1]['ip']
    PORT_UASERVER = int(cHandler.datos_config[1][1]['puerto'])
    PORT_RTP = int(cHandler.datos_config[2][1]['puerto'])

    fichero_audio = cHandler.datos_config[5][1]['path']
    if not os.path.isfile(fichero_audio):
        sys.exit('File Error: ' + fichero_audio + ' does not exist')

    print("Listening...")

    serv = socketserver.UDPServer((IP_UASERVER, PORT_UASERVER), EchoHandler)

    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print('Finalizado servidor')
