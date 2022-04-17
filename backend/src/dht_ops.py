import grpc

from hashlib import sha1
from typing import Optional

import backend_pb2 as bs
import backend_pb2_grpc as bss


def dht_lookup(key: str, start_addr: str) -> str:
    target_hash = sha1(key.encode()).hexdigest()
    curr_addr = start_addr
    curr_hash = sha1(curr_addr.encode()).hexdigest()

    min_hash_addr = curr_addr
    min_hash = curr_hash

    while True:
        curr_stub = bss.BackendServiceStub(grpc.insecure_channel(curr_addr))
        succ_opt = curr_stub.GetSucc(bs.NullMessage())
        if not succ_opt.hasValue:
            return curr_addr
        succ_addr = succ_opt.nodeAddress.address
        succ_hash = sha1(succ_addr.encode()).hexdigest()
        if target_hash < succ_hash and target_hash > curr_hash:
            return succ_addr
        curr_addr = succ_addr
        curr_hash = succ_hash
        if curr_hash < min_hash:
            min_hash = curr_hash
            min_hash_addr = curr_addr
        if curr_addr == start_addr:
            break
    return min_hash_addr


def dht_set(key: str, val: str, start_addr: str) -> None:
    target_addr = dht_lookup(key, start_addr)
    key_hash = sha1(key.encode()).hexdigest()
    target_stub = bss.BackendServiceStub(grpc.insecure_channel(target_addr))
    target_stub.SetItem(
        bs.StoredItem(
            hash=key_hash,
            data=val
        )
    )


def dht_get(key: str, start_addr: str) -> Optional[str]:
    target_addr = dht_lookup(key, start_addr)
    key_hash = sha1(key.encode()).hexdigest()
    target_stub = bss.BackendServiceStub(grpc.insecure_channel(target_addr))
    item_opt = target_stub.GetItem(bs.ItemHash(hash=key_hash))
    if item_opt.hasValue:
        return item_opt.storedItem.data
    return None
