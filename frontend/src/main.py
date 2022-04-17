import argparse
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
    def __init__(self, backend_addr: str, self_addr: str):
        super().__init__()
        self.__backend = bss.BackendServiceStub(grpc.insecure_channel(backend_addr))
        self.__addr = self_addr
        self.__registered = False


    def run(self):
        while True:
            cmd = input('|||| ')
            if cmd == 'help':
                print('help send list reg quit')
            elif cmd == 'list':
                for message in messages:
                    u = message.sender
                    if u is None or u == '':
                        u = '?'
                    t = message.text
                    print(f'{u} : {t}')
            elif cmd == 'send':
                if not self.__registered:
                    print('not registered.')
                    continue
                rec = input('to: ')
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
            elif cmd == 'reg':
                username = input('username: ')
                resp = self.__backend.Connect(bs.ConnectInfo(
                    username=username,
                    frontendUrl=self.__addr
                ))
                if resp.ok:
                    print('registered.')
                    self.__registered = True
                else:
                    print(resp.desc)
            else:
                print('unknown cmd.')
            

def main():
    parser = argparse.ArgumentParser(description='whisper demo text ui')
    parser.add_argument('host', type=str, help='ui host address')
    parser.add_argument('node', type=str, help='node address')
    args = parser.parse_args()

    ui = UserInterface(args.node, args.host)
    ui.start()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    fss.add_FrontendServiceServicer_to_server(FrontendServicer(), server)
    server.add_insecure_port(args.host)
    server.start()
    server.wait_for_termination()



if __name__ == '__main__':
    main()
