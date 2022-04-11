import grpc
import threading

from dataclasses import dataclass
from typing import List, Optional
from concurrent import futures

import backend_pb2 as bs
import backend_pb2_grpc as bss
import frontend_pb2 as fs
import frontend_pb2_grpc as fss


@dataclass
class Message:
    text: str
    sender: Optional[str]


messages: List[Message] = []


class FrontendServicer(fss.FrontendServiceServicer):
    def ProcessNewMessage(self, request, context):
        messages.append(Message(request.text, request.username))
        return fs.FsSimpleResponse(ok=True)


class UserInterface(threading.Thread):
    def __init__(self, backend_port: int, whisper_port: int, redock_port: int, listener_port: int, docker_url: str, username: str):
        super().__init__()
        self.__backend_port = backend_port
        self.__whisper_port = whisper_port
        self.__redock_port = redock_port
        self.__listener_port = listener_port
        self.__docker_url = docker_url
        self.__username = username
        self.__channel = None
        self.__backend = None


    def run(self):
        while True:
            cmd = input('|||| ')
            if cmd == 'help':
                print('help send list connect quit')
            elif cmd == 'list':
                for message in messages:
                    u = message.sender
                    if u is None or u == '':
                        u = '?'
                    t = message.text
                    print(f'{u} : {t}')
            elif cmd == 'send':
                if self.__backend is None:
                    print('not connected')
                    continue
                for u in self.__backend.GetUsers(bs.User(username='')):
                    print(u.username)
                rec = input('? ')
                sign = input('sign? y/n: ') == 'y'
                ttl = int(input('ttl: '))
                text = input('text: ')
                resp = self.__backend.SendMessage(bs.Message(
                    username=rec,
                    text=text,
                    sign=sign,
                    ttl=ttl
                ))
                if resp.ok:
                    print('ok.')
                else:
                    print(resp.desc)
            elif cmd == 'connect':
                self.__channel = grpc.insecure_channel(f'localhost:{self.__backend_port}')
                self.__backend = bss.BackendServiceStub(self.__channel)
                resp = self.__backend.Connect(bs.ConnectInfo(
                    username=self.__username,
                    dockingUrl = self.__docker_url,
                    redockPort = self.__redock_port,
                    whisperPort = self.__whisper_port,
                    frontendUrl = f'localhost:{self.__listener_port}'
                ))
                if resp.ok:
                    print('connected.')
                else:
                    print(resp.desc)
            else:
                print('unknown cmd.')
            

def main():
    backend_port = int(input('backend port: '))
    whisper_port = int(input('whisper port: '))
    redock_port = int(input('redock port: '))
    listener_port = int(input('listener port: '))
    docker_url = input('docker url: ')
    username = input('username: ')

    ui = UserInterface(backend_port, whisper_port, redock_port, listener_port, docker_url, username)
    ui.start()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    fss.add_FrontendServiceServicer_to_server(FrontendServicer(), server)
    server.add_insecure_port(f'[::]:{listener_port}')
    server.start()
    server.wait_for_termination()



if __name__ == '__main__':
    main()
