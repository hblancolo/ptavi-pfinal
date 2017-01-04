#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Clase (y programa principal) para un servidor de eco en UDP simple
"""

import sys
import socketserver
import socket
import time
import json
import hashlib
from xml.sax import make_parser
from xml.sax.handler import ContentHandler


def event2log(event):
    event = (" ").join(event.split())  # cambio saltos de linea por espacios
    date = time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()))
    log_line = date + ' ' + event + '\n'
    with open(LOG_PATH, 'a') as log_file:
        log_file.write(log_line)


class XMLHandler(ContentHandler):

    def __init__(self):
        self.datos_config = []  # lista de listas. cada sublista tiene dos
#elementos:el primero es el nombre de etiqueta, el segundo el dicc de atributos
        attrs_server = ['name', 'ip', 'puerto']
        attrs_database = ['path', 'passwdpath']
        attrs_log = ['path']
        self.dicc_etiquetas = {'server': attrs_server,
                               'database': attrs_database,
                               'log': attrs_log}

    def startElement(self, name, attrs):
        if name in self.dicc_etiquetas:
            dicc = {}
            for attr in self.dicc_etiquetas[name]:
                dicc[attr] = attrs.get(attr, "")

            self.datos_config.append([name, dicc])

    def get_tags(self):
        return self.datos_config


class SIPRegisterHandler(socketserver.DatagramRequestHandler):
    """
    Echo server class
    """

    dic = {}  # almacena nombre usuario e ip correspondiente cuando REGISTER
    dest_user = ['']  # variable global, para guardar el nombre del usuario
                      # invitado y poder sacar sus parametros al recibir el ACK
                      # del cliente
    nonce = '898989898798989898989'

    def check_expires(self):
        """
        Comprueba que en el registro de usuarios (self.dic) no haya ningún
        usuario caducado. Si hay usuarios caducados, los borra
        """
        expired_users = []
        for usuario in self.dic:
            time_now = time.time()
            user_expires = (self.dic[usuario][2]['register_date'] +
                            float(self.dic[usuario][3]['expire_time']))
            if time_now >= user_expires:
                expired_users.append(usuario)

        for usuario in expired_users:
            del self.dic[usuario]

    def register2json(self):
        """
        Vuelca el registro de usuarios (self.dic) en un fichero json, para
        poder almacenarlo en la memoria estática
        """
        fich_json = open(PATH_Register, 'w')
        codigo_json = json.dumps(self.dic)
        fich_json.write(codigo_json)
        fich_json.close()

    def json2registered(self):
        """
        Si existe un fichero registered.json con un registro almacenado, lo
        utiliza en el servidor Registrar
        """
        try:
            fich_json = open('registered.json', 'r')
            self.dic = json.load(fich_json)
        except:
            pass

    def handle(self):
        """
        Manejador de peticiones de cliente. Sólo hace algo cuando recibe
        peticiones tipo REGISTER
        """
        valid_request = False
        valid_method = False
        valid_user = False
        proxy_methods = ['REGISTER', 'INVITE', 'ACK', 'BYE']
        line_str = self.rfile.read().decode('utf-8')
        list_linecontent = line_str.split()
        method = list_linecontent[0]
        event2log(('Received from ' + self.client_address[0] + ':' +
                   str(self.client_address[1]) + ' ' + line_str))

        #self.json2registered()

        # Condiciones iniciales para funcionamiento del proxy/registrar
        if len(list_linecontent) >= 3:
            valid_request = True
        else:
            self.wfile.write(b'SIP/2.0 400 Bad Request\r\n\r\n')
            event2log(('Sent to ' + self.client_address[0] + ':' +
                       str(self.client_address[1]) + ' ' +
                       'SIP/2.0 400 Bad Request\r\n\r\n'))
        if method in proxy_methods:
            valid_method = True
        else:
            self.wfile.write(b'SIP/2.0 405 Method Not Allowed\r\n\r\n')
            event2log(('Sent to ' + self.client_address[0] + ':' +
                       str(self.client_address[1]) + ' ' +
                       'SIP/2.0 405 Method Not Allowed\r\n\r\n'))

        if valid_method and valid_request:
            if method == 'REGISTER':
                user = list_linecontent[1].split(':')[1]
                for elem in allowed_users:
                    if elem['user'] == user:
                        valid_user = True
                        passwd = elem['password']
                        ip_ua = self.client_address[0]
                        port_ua = list_linecontent[1].split(':')[-1]

                if ('Digest' in list_linecontent) and (valid_user is True):
                    hash_received = line_str.split('"')[1]
                    authenticate = hashlib.md5()
                    authenticate.update(bytes(passwd, 'utf-8'))
                    authenticate.update(bytes(self.nonce, 'utf-8'))
                    authenticate.digest
                    if hash_received == authenticate.hexdigest():
                        self.dic[user] = [{'ip': ip_ua},
                                          {'port': port_ua},
                                          {'register_date': time.time()},
                                          {'expire_time': list_linecontent[4]}]
                        self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
                        event2log(('Sent to ' + self.client_address[0] + ':' +
                                   str(self.client_address[1]) + ' ' +
                                   'SIP/2.0 200 OK\r\n\r\n'))

                    else:
                        print('Client password is not correct')
                        self.wfile.write(b'SIP/2.0 400 Bad Request\r\n\r\n')
                        event2log(('Sent to ' + self.client_address[0] + ':' +
                                   str(self.client_address[1]) + ' ' +
                                   'SIP/2.0 400 Bad Request\r\n\r\n'))

                elif ('Digest' not in list_linecontent) and (valid_user is
                                                             False):
                    print('Error: Unknown user trying to register')
                    self.wfile.write(bytes("SIP/2.0 401 Unauthorized\r\n" +
                                           'WWW Authenticate: Digest nonce="' +
                                           self.nonce + '"\r\n\r\n', 'utf-8'))
                    event2log(('Sent to ' + self.client_address[0] + ':' +
                               str(self.client_address[1]) + ' ' +
                               "SIP/2.0 401 Unauthorized\r\n" +
                               'WWW Authenticate: Digest nonce="' +
                               self.nonce + '"\r\n\r\n'))
                else:
                    self.wfile.write(bytes("SIP/2.0 401 Unauthorized\r\n" +
                                           'WWW Authenticate: Digest nonce="' +
                                           self.nonce + '"\r\n\r\n', 'utf-8'))
                    event2log(('Sent to ' + self.client_address[0] + ':' +
                               str(self.client_address[1]) + ' ' +
                               "SIP/2.0 401 Unauthorized\r\n" +
                               'WWW Authenticate: Digest nonce="' +
                               self.nonce + '"\r\n\r\n'))

            elif method == 'INVITE':
                invited_user = list_linecontent[1].split(':')[1]
                registered_user = False
                for usuario in self.dic:
                    if invited_user == usuario:
                        registered_user = True
                        ip_invited_user = self.dic[invited_user][0]['ip']
                        port_invited_user = self.dic[invited_user][1]['port']
                        port_invited_user = int(port_invited_user)
                        self.dest_user[0] = invited_user  # lo guardo en
                                                          # variable global
                if registered_user is True:
                    try:
                        my_socket = socket.socket(socket.AF_INET,
                                                  socket.SOCK_DGRAM)
                        my_socket.setsockopt(socket.SOL_SOCKET,
                                             socket.SO_REUSEADDR, 1)
                        my_socket.connect((ip_invited_user,
                                           port_invited_user))
                        event2log('Starting socket...')

                        my_socket.send(bytes(line_str, 'utf-8')+b'\r\n\r\n')
                        event2log(('Sent to ' + ip_invited_user + ':' +
                                   str(port_invited_user) + ' ' + line_str))

                        data = my_socket.recv(1024)
                        received_line = data.decode('utf-8')
                        print('Recibido del servidor: ', received_line)
                        event2log(('Received from ' + ip_invited_user + ':' +
                                   str(port_invited_user) + ' ' +
                                   received_line))

                        self.wfile.write(data)
                        event2log(('Sent to ' + self.client_address[0] + ':' +
                                   str(self.client_address[1]) + ' ' +
                                   received_line))

                        my_socket.close()
                        event2log('Finishing socket.')

                    except ConnectionRefusedError:
                        print('No server listening at: ' + ip_invited_user +
                              ' port ' + str(port_invited_user))
                        event2log('Error: No server listening at ' +
                                  ip_invited_user + ' port ' +
                                  str(port_invited_user))

                else:
                    self.wfile.write(b'SIP/2.0 404 User Not Found\r\n\r\n')
                    event2log(('Sent to ' + self.client_address[0] + ':' +
                               str(self.client_address[1]) + ' ' +
                               'SIP/2.0 404 User Not Found\r\n\r\n'))

            elif method == 'ACK':
                invited_user = self.dest_user[0]
                ip_invited_user = self.dic[invited_user][0]['ip']
                port_invited_user = int(self.dic[invited_user][1]['port'])

                try:
                    my_socket = socket.socket(socket.AF_INET,
                                              socket.SOCK_DGRAM)
                    my_socket.setsockopt(socket.SOL_SOCKET,
                                         socket.SO_REUSEADDR, 1)
                    my_socket.connect((ip_invited_user, port_invited_user))
                    event2log('Starting socket...')

                    my_socket.send(bytes(line_str, 'utf-8') + b'\r\n\r\n')
                    event2log(('Sent to ' + ip_invited_user + ':' +
                               str(port_invited_user) + ' ' + line_str))

                    my_socket.close()
                    event2log('Finishing socket.')
                except ConnectionRefusedError:
                    self.wfile.write(b'SIP/2.0 404 User Not Found\r\n\r\n')
                    event2log(('Sent to ' + self.client_address[0] + ':' +
                               str(self.client_address[1]) + ' ' +
                               'SIP/2.0 404 User Not Found\r\n\r\n'))
            elif method == 'BYE':
                invited_user = self.dest_user[0]
                ip_invited_user = self.dic[invited_user][0]['ip']
                port_invited_user = int(self.dic[invited_user][1]['port'])

                try:
                    my_socket = socket.socket(socket.AF_INET,
                                              socket.SOCK_DGRAM)
                    my_socket.setsockopt(socket.SOL_SOCKET,
                                         socket.SO_REUSEADDR, 1)
                    my_socket.connect((ip_invited_user, port_invited_user))
                    event2log('Starting socket...')

                    my_socket.send(bytes(line_str, 'utf-8')+b'\r\n\r\n')
                    event2log(('Sent to ' + ip_invited_user + ':' +
                               str(port_invited_user) + ' ' + line_str))

                    data = my_socket.recv(1024)
                    received_line = data.decode('utf-8')
                    event2log(('Received from ' + ip_invited_user + ':' +
                               str(port_invited_user) + ' ' + received_line))

                    self.wfile.write(data)
                    event2log(('Sent to ' + self.client_address[0] + ':' +
                               str(self.client_address[1]) + ' ' +
                               received_line))

                    my_socket.close()
                    event2log('Finishing socket.')

                except ConnectionRefusedError:
                    self.wfile.write(b'SIP/2.0 404 User Not Found\r\n\r\n')
                    event2log(('Sent to ' + self.client_address[0] + ':' +
                               str(self.client_address[1]) + ' ' +
                               'SIP/2.0 404 User Not Found\r\n\r\n'))

        self.check_expires()
        self.register2json()

if __name__ == "__main__":
    try:
        CONFIG = sys.argv[1]
    except:
        sys.exit('Usage: python proxy_registrar.py config')

    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))

    LOG_PATH = cHandler.datos_config[2][1]['path']
    event2log('Starting...')

    # Obtención de datos del fichero de configuración
    if cHandler.datos_config[0][1]['ip'] != '':
        IP_PROXY = cHandler.datos_config[0][1]['ip']
    else:
        IP_PROXY = '127.0.0.1'
    PORT_PROXY = int(cHandler.datos_config[0][1]['puerto'])
    NAME_PROXY = cHandler.datos_config[0][1]['name']
    PATH_Register = cHandler.datos_config[1][1]['path']
    PATH_Passwords = cHandler.datos_config[1][1]['passwdpath']

    # Extraccion de los users y passwords del fichero passwdpath
    allowed_users = []  # almacena los users y passwd que hay en passwords.txt
    passwd_file = open(PATH_Passwords, 'r')
    for line in passwd_file.readlines():
        u = line.split(' ')[1]
        p = line.split(' ')[3][0:-1]  # con [0:-1] eliminamos el /n
        d = {'user': u, 'password': p}
        allowed_users.append(d)

    # Puesta en funcionamiento del proxy/registrar
    serv = socketserver.UDPServer((IP_PROXY, PORT_PROXY), SIPRegisterHandler)
    print('Server ' + NAME_PROXY + ' listening at port ' +
          str(PORT_PROXY)+'...')
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print("Server finished.")
        event2log('Finishing.')
