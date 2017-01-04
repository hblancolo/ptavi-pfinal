#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import socket
import time
import hashlib
import os
from xml.sax import make_parser
from xml.sax.handler import ContentHandler


class XMLHandler(ContentHandler):

    def __init__(self):
        self.datos_config = []  # lista de listas. cada sublista tiene dos
# elementos:el 1º es el nombre de etiqueta, el 2º el dicc de atributos
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
                               'audio': attrs_audio}

    def startElement(self, name, attrs):
        if name in self.dicc_etiquetas:
            dicc = {}
            for attr in self.dicc_etiquetas[name]:
                dicc[attr] = attrs.get(attr, "")

            self.datos_config.append([name, dicc])

    def get_tags(self):
        return self.datos_config


def event2log(event):
    event = (" ").join(event.split())  # cambio saltos de linea por espacios
    date = time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()))
    log_line = date + ' ' + event + '\n'
    with open(LOG_PATH, 'a') as log_file:
        log_file.write(log_line)

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

    LOG_PATH = cHandler.datos_config[4][1]['path']
    event2log('Starting Client...')

    # Extracción de datos del fichero de configuración del UA
    IP_PROXY = cHandler.datos_config[3][1]['ip']
    PORT_PROXY = int(cHandler.datos_config[3][1]['puerto'])
    USER_NAME = cHandler.datos_config[0][1]['username']
    PASSWD = cHandler.datos_config[0][1]['passwd']
    PORT_UASERVER = int(cHandler.datos_config[1][1]['puerto'])
    PORT_RTP = int(cHandler.datos_config[2][1]['puerto'])
    if cHandler.datos_config[1][1]['ip'] != '':
        IP_UASERVER = cHandler.datos_config[1][1]['ip']
    else:
        IP_UASERVER = '127.0.0.1'
    fichero_audio = cHandler.datos_config[5][1]['path']
    if not os.path.isfile(fichero_audio):
        sys.exit('File Error: ' + fichero_audio + ' does not exist.')
        event2log(('Error: the file ' + fichero_audio + ' does not exist.'))

    # Comienzo de la comunicación con el proxy/registrar
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        my_socket.connect((IP_PROXY, PORT_PROXY))

        if METHOD == 'REGISTER':
            LINE = (METHOD + ' sip:' + USER_NAME + ':' + str(PORT_UASERVER) +
                    ' SIP/2.0\r\nExpires: ' + str(OPTION))
        elif METHOD == 'INVITE':
            if OPTION == USER_NAME:
                sys.exit('Error: you are inviting yourself.')
            BODY = ('v=0\r\no=' + USER_NAME + ' ' + IP_UASERVER +
                    '\r\ns=misesion\r\nt=0\r\nm=audio '+str(PORT_RTP) + ' RTP')
            LINE = (METHOD + ' sip:' + OPTION +
                    ' SIP/2.0\r\nContent-Type: application/sdp\r\n\r\n' + BODY)
        elif METHOD == 'BYE':
            if OPTION == USER_NAME:
                sys.exit('Error: you are saying "BYE" to yourself. Try to say'
                         '"BYE" to the one you have invited before.')
            LINE = (METHOD + ' sip:' + USER_NAME + ':' + str(PORT_UASERVER) +
                    ' SIP/2.0\r\nExpires: ' + str(OPTION))

        my_socket.send(bytes(LINE, 'utf-8') + b'\r\n\r\n')
        event2log(('Sent to ' + IP_PROXY + ':' + str(PORT_PROXY) + ' ' + LINE))

        data = my_socket.recv(1024)
        received_line = data.decode('utf-8')
        print('Received -- ', received_line)
        event2log(('Received from ' + IP_PROXY + ':' + str(PORT_PROXY) +
                   ' ' + received_line))

        confirmation_invite = ('SIP/2.0 100 Trying\r\n\r\n'
                               'SIP/2.0 180 Ring\r\n\r\n'
                               'SIP/2.0 200 OK\r\n')

        if (METHOD == 'REGISTER') and ('SIP/2.0 401' in received_line):
            nonce = received_line.split('"')[1]
            authenticate = hashlib.md5()
            authenticate.update(bytes(PASSWD, 'utf-8'))
            authenticate.update(bytes(nonce, 'utf-8'))
            authenticate.digest
            LINE = (METHOD + ' sip:' + USER_NAME + ':' + str(PORT_UASERVER) +
                    ' SIP/2.0\r\nExpires: ' + str(OPTION) + '\r\n' +
                    'Authorization: Digest response="' +
                    authenticate.hexdigest() + '"')
            my_socket.send(bytes(LINE, 'utf-8') + b'\r\n\r\n')
            event2log(('Sent to ' + IP_PROXY + ':' + str(PORT_PROXY) +
                       ' ' + LINE))

            data = my_socket.recv(1024)
            received_line = data.decode('utf-8')
            print('Received -- ', received_line)
            event2log(('Received from ' + IP_PROXY + ':' + str(PORT_PROXY) +
                       ' ' + received_line))

        elif (METHOD == 'INVITE') and (received_line.split('Content-Type')[0]
                                       == confirmation_invite):
            METHOD = 'ACK'
            LINE = (METHOD + ' sip:' + USER_NAME + ':' + str(PORT_UASERVER) +
                    ' SIP/2.0')
            my_socket.send(bytes(LINE, 'utf-8') + b'\r\n\r\n')
            print('ACK transmitted. Starting rtp transmission...')
            event2log(('Sent to ' + IP_PROXY + ':' + str(PORT_PROXY) +
                       ' ' + LINE))

            sdp_received = received_line.split('\r\n\r\n')[-2]
            ip_server = sdp_received.split('\r\n')[1].split(' ')[1]
            p_rtp_server = sdp_received.split('\r\n')[4].split(' ')[1]
            os.system('./mp32rtp -i ' + ip_server + ' -p ' +
                      p_rtp_server + ' < ' + fichero_audio)
            print('RTP transmission finished')
            event2log(('Sent to ' + ip_server + ':' + str(p_rtp_server) +
                       ' ' + fichero_audio + ' via RTP protocol'))

        my_socket.close()
        print("Client finished.")
        event2log('Client Finished.')

    except ConnectionRefusedError:
        print('Error: No server listening at ' + IP_PROXY + ' port ' +
              str(PORT_PROXY))
        event2log('Error: No server listening at ' + IP_PROXY + ' port ' +
                  str(PORT_PROXY))
