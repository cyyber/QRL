# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from qrl.generated import qrlstateinfo_pb2


class HookPool:

    def __init__(self, pbdata=None):
        self._data = pbdata
        if not pbdata:
            self._data = qrlstateinfo_pb2.HookPool()

    @property
    def pool(self):
        return self._data.pool

    def serialize(self) -> str:
        return self._data.SerializeToString()

    def add(self, contract_address: bytes):
        self._data.pool.extend([contract_address])

    @staticmethod
    def deserialize(data):
        pbdata = qrlstateinfo_pb2.HookPool()
        pbdata.ParseFromString(bytes(data))
        return HookPool(pbdata)
