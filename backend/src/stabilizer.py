import threading
import grpc
import time

from node_data import NodeData, StoredItem

import backend_pb2 as bs
import backend_pb2_grpc as bss


class Stabilizer(threading.Thread):
    def __init__(self, node_data: NodeData):
        super().__init__()
        self.__node_data = node_data

    def __maintain_succ_pred(self):
        succ_stub = bss.BackendServiceStub(grpc.insecure_channel(self.__node_data.succ))
        succ_pred_opt = succ_stub.GetPred(bs.NullMessage())
        update_items = False
        if not succ_pred_opt.hasValue:
            print('succ pred is none')
            succ_stub.Dock(bs.NodeAddress(address=self.__node_data.addr))
            update_items = True
        elif succ_pred_opt.nodeAddress.address != self.__node_data.addr:
            update_items = True
            print(f'succ pred is {succ_pred_opt.nodeAddress.address}')
            succ_pred_stub = bss.BackendServiceStub(grpc.insecure_channel(succ_pred_opt.nodeAddress.address))
            succ_pred_stub.Dock(bs.NodeAddress(address=self.__node_data.addr))
            self.__node_data.succ = succ_pred_opt.nodeAddress.address
        if update_items:
            succ_stub = bss.BackendServiceStub(grpc.insecure_channel(self.__node_data.succ))
            for item in succ_stub.CopyData(bs.NodeAddress(address=self.__node_data.addr)):
                if all(map(lambda i: i.hash != item.hash,  self.__node_data.stored_items)):
                    stored_item = StoredItem(item.hash, item.data)
                    self.__node_data.stored_items.append(stored_item)


    def run(self):
        print('stabilizer started')
        while True:
            time.sleep(10)
            with self.__node_data.lock:
                if self.__node_data.succ is None:
                    continue

                self.__maintain_succ_pred()

                print(f'pred: {self.__node_data.pred}')
                print(f'succ: {self.__node_data.succ}')
