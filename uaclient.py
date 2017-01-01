#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import socket
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

class XMLHandler(ContentHandler):

    def __init__(self):
        self.datos_config = []  # lista de listas. cada sublista tiene dos elementos:el primero es el nombre de etiqueta, el segundo el dicc de atributos
        attrs_account = ['username', 'passwd']
        attrs_uaserver = ['ip', 'puerto']
        attrs_rtpaudio = ['puerto']
        attrs_regproxy = ['ip', 'puerto']
        attrs_log = ['path']
        attrs_audio = ['path']
        self.dicc_etiquetas = {'account': attrs_account,
                               'uaserver': attrs_uaserver,
                               'rtpaudio': attrs_rtpaudio,
                               'regproxy': attrs_regproxy,
                               'log': attrs_log,  
                               'audio': attrs_audio,}

    def startElement(self, name, attrs):
        if name in self.dicc_etiquetas:
            dicc = {}
            for attr in self.dicc_etiquetas[name]:
                dicc[attr] = attrs.get(attr, "")

            self.datos_config.append([name, dicc])

    def get_tags(self):

        return self.datos_config

if __name__ == "__main__":

    try:
        CONFIG = sys.argv[1]
        METHOD = sys.argv[2].upper()  # upper me lo pone en mayusculas
        if METHOD == 'REGISTER':
            OPTION = int(sys.argv[3])
        elif METHOD == 'INVITE' or METHOD == 'BYE':
            OPTION = sys.argv[3]
        else:
            sys.exit('Unknown method')
    except:
        sys.exit('Usage: python uaclient.py config method option')

    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))

    IP_PROXY = cHandler.datos_config[3][1]['ip']
    PORT_PROXY = int(cHandler.datos_config[3][1]['puerto'])
    USER_NAME = cHandler.datos_config[0][1]['username']
    IP_UASERVER = cHandler.datos_config[1][1]['ip']
    PORT_UASERVER = int(cHandler.datos_config[1][1]['puerto'])
    PORT_RTP = int(cHandler.datos_config[2][1]['puerto'])

    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((IP_PROXY, PORT_PROXY))
# (SIN HACER) en caso de intentar establecer conexión con un puerto no abierto, se capturará la excepción , y antes de finalizar el programa se incluirá en el log un mensaje como éste: 20101018160243 Error: No server listening at 193.147.73 port

    if METHOD == 'REGISTER':
        LINE = (METHOD + ' sip:' + USER_NAME + ':' + str(PORT_UASERVER) + 
                ' SIP/2.0\r\nExpires: ' + str(OPTION))
    elif METHOD == 'INVITE':
        BODY = ('v=0\r\no=' + USER_NAME + ' ' + IP_UASERVER +
                '\r\ns=misesion\r\nt=0\r\nm=audio ' + str(PORT_RTP) + ' RTP')
        LINE = (METHOD + ' sip:' + OPTION + 
                ' SIP/2.0\r\nContent-Type: application/sdp\r\n\r\n' + BODY)
    elif METHOD == 'BYE':
        LINE = (METHOD + ' sip:' + USER_NAME + ':' + str(PORT_UASERVER) + 
                ' SIP/2.0\r\nExpires: ' + str(OPTION))

    my_socket.send(bytes(LINE, 'utf-8') + b'\r\n\r\n')

    data = my_socket.recv(1024)
    received_line = data.decode('utf-8')
    print('Recibido -- ', received_line)
    error401 = ('SIP/2.0 401 Unauthorized\r\nWWW Authenticate: '
                'Digest nonce="898989898798989898989"\r\n\r\n')
    confirmation_invite = ('SIP/2.0 100 Trying\r\n\r\n'
                           'SIP/2.0 180 Ring\r\n\r\n'
                           'SIP/2.0 200 OK\r\n\r\n')
    
    if (METHOD == 'REGISTER') and (received_line == error401):
        LINE = (METHOD + ' sip:' + USER_NAME + ':' + str(PORT_UASERVER) + 
                ' SIP/2.0\r\nExpires: ' + str(OPTION) + '\r\n' +
                'Authorization: Digest response="123123212312321212123"')
        my_socket.send(bytes(LINE, 'utf-8') + b'\r\n\r\n')
        data = my_socket.recv(1024)
        received_line = data.decode('utf-8')
        print('Recibido -- ', received_line)

    elif (METHOD == 'INVITE') and (confirmation_invite + BODY + '\r\n\r\n'):
        METHOD = 'ACK'
        LINE = (METHOD + ' sip:' + USER_NAME + ':' + str(PORT_UASERVER) +
                ' SIP/2.0')
        my_socket.send(bytes(LINE, 'utf-8') + b'\r\n\r\n')

    
    print("Terminando socket...")
    my_socket.close()
    print("Fin.")




