from pyqrllib.pyqrllib import bin2hstr

from qrl.core import config
from qrl.core.AddressState import AddressState
from qrl.core.misc import logger
from qrl.core.txs.Transaction import Transaction
from qrl.crypto.misc import sha256


class Contract(Transaction):
    """
    DeployContract for the transaction of QRL from one wallet to another.
    """

    def __init__(self, protobuf_transaction=None):
        super(Contract, self).__init__(protobuf_transaction)

    @property
    def byte_code(self):
        return self._data.contract.byte_code

    @property
    def amount(self):
        return self._data.contract.amount

    @property
    def hook(self):
        """
        Read byte_code and detect future blockheight to hook, in case of no hook,
        return the current blockheight as hook which will result into immediate
        execution of contract.
        :return:
        """
        return None

    def get_data_hash(self):
        tmptxhash = (self.master_addr +
                     self.fee.to_bytes(8, byteorder='big', signed=False) +
                     self.byte_code +
                     self.amount)

        return sha256(tmptxhash)

    @staticmethod
    def create(byte_code: bytes, amount: int, fee: int, xmss_pk, master_addr: bytes = None):
        transaction = Contract()

        if master_addr:
            transaction._data.master_addr = master_addr

        transaction._data.public_key = bytes(xmss_pk)

        transaction._data.contract.code = byte_code
        transaction._data.contract.amount = int(amount)

        transaction._data.fee = int(fee)

        transaction.validate_or_raise(verify_signature=False)

        return transaction

    def _validate_custom(self):
        if self.amount == 0:
            logger.warning('Amount cannot be 0 - %s', self.amount)
            logger.warning('Invalid TransferTransaction')
            return False

        if self.fee < 0:
            raise ValueError('Contract [%s] Invalid Fee = %d', bin2hstr(self.txhash), self.fee)

        if not AddressState.address_is_valid(self.addr_from):
            logger.warning('[Contract] Invalid address addr_from: %s', self.addr_from)
            return False

        return True

    # checks new tx validity based upon node statedb and node mempool.
    def validate_extended(self, addr_from_state: AddressState, addr_from_pk_state: AddressState):
        if not self.validate_slave(addr_from_state, addr_from_pk_state):
            return False

        if len(self.byte_code) > config.dev.max_allowed_code_size:
            logger.warning('[Contract] code is greater than the allowed length')
            logger.warning('Length found: %s, Max allowed length: %s', len(self.byte_code), config.dev.max_allowed_code_size)
            return False

        tx_balance = addr_from_state.balance

        if tx_balance < self.amount + self.fee:
            logger.info('[Contract] State validation failed for %s because: Insufficient funds', bin2hstr(self.txhash))
            logger.info('balance: %s, fee: %s, amount: %s', tx_balance, self.fee, self.amount)
            return False

        if addr_from_pk_state.ots_key_reuse(self.ots_key):
            logger.info('[Contract] State validation failed for %s because: OTS Public key re-use detected', bin2hstr(self.txhash))
            return False

        return True

    def apply_state_changes(self, addresses_state: dict):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance -= (self.amount + self.fee)
            addresses_state[self.addr_from].transaction_hashes.append(self.txhash)

        self._apply_state_changes_for_PK(addresses_state)

    def revert_state_changes(self, addresses_state, chain_manager):
        if self.addr_from in addresses_state:
            addresses_state[self.addr_from].balance += (self.amount + self.fee)
            addresses_state[self.addr_from].transaction_hashes.remove(self.txhash)

        self._revert_state_changes_for_PK(addresses_state, chain_manager)

    def set_affected_address(self, addresses_set: set):
        super().set_affected_address(addresses_set)
