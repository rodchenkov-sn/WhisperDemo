import argparse
import grpc

from concurrent import futures

from backend_servicer import BackendServicer

import backend_pb2_grpc as bss


def main():
    parser = argparse.ArgumentParser(description='whisper demo node')
    parser.add_argument('host', type=str, help='node host address')
    parser.add_argument('-t', '--target', type=str, help='known node address', default=None)
    args = parser.parse_args()

    host = args.host
    known_node = args.target

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    bss.add_BackendServiceServicer_to_server(BackendServicer(host, known_node), server)
    server.add_insecure_port(host)
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    main()
