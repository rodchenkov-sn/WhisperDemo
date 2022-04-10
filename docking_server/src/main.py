from dataclasses import dataclass
from typing import Optional

import requests
import sys

from flask import Flask, request, jsonify, abort


app = Flask(__name__)


@dataclass
class Client:
    base: str
    whisper_port: int
    redock_port: int


@dataclass
class NetInfo:
    head: Optional[Client]
    tail: Optional[Client]


netinfo = NetInfo(None, None)


def request_redock(source: Client, target: Client):
    adr = f'http://{source.base}:{source.redock_port}/redock'
    requests.post(adr, json={'next': f'{target.base}:{target.whisper_port}'})


@app.errorhandler(400)
def bad_request(error):
    return jsonify({ 'error': 'Bad request' }), 400


@app.post("/dock")
def add_new_peer():
    if not request.json:
        abort(400)
    ip = request.environ['REMOTE_ADDR']
    whisper_port = request.json['whisper_port']
    redock_port = request.json['redock_port']
    new_tail = Client(ip, whisper_port, redock_port)
    print(f'==> docking {new_tail}', file=sys.stdout)
    if netinfo.head is None:
        netinfo.head = Client(ip, whisper_port, redock_port)
        netinfo.tail = Client(ip, whisper_port, redock_port)
    else:
        request_redock(netinfo.tail, new_tail)
    netinfo.tail = new_tail
    return jsonify({'next': f'{netinfo.head.base}:{netinfo.head.whisper_port}'}), 200


def main():
    port = int(input('port: '))
    app.run(host='0.0.0.0', port=port, debug=False)


if __name__ == '__main__':
    main()
