# coding=utf-8
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
import copy
from typing import Optional

from pyqrllib.pyqrllib import bin2hstr
from pyqryptonight.pyqryptonight import Qryptominer, StringToUInt256, UInt256ToString

from qrl.core import config
from qrl.core.Block import Block
from qrl.core.DifficultyTracker import DifficultyTracker
from qrl.core.PoWValidator import PoWValidator
from qrl.core.State import State
from qrl.core.TransactionPool import TransactionPool
from qrl.core.Transaction import MessageTransaction, LatticePublicKey, SlaveTransaction
from qrl.core.Transaction import Transaction, TransferTransaction, TokenTransaction, TransferTokenTransaction
from qrl.core.misc import logger
from qrl.crypto.xmss import XMSS


class Miner(Qryptominer):
    def __init__(self,
                 pre_block_logic,
                 mining_credit_wallet: bytes,
                 state: State,
                 mining_thread_count,
                 add_unprocessed_txn_fn):
        super().__init__()
        self.pre_block_logic = pre_block_logic  # FIXME: Circular dependency with node.py

        self._mining_block = None
        self._current_difficulty = None
        self._current_target = None
        self._measurement = None  # Required only for logging

        self._mining_credit_wallet = mining_credit_wallet
        self._mining_xmss = None
        self._reward_address = None
        self.state = state
        self._add_unprocessed_txn_fn = add_unprocessed_txn_fn
        self._mining_thread_count = mining_thread_count
        self._dummy_xmss = None

    @staticmethod
    def set_unused_ots_key(xmss, addr_state, start=0):
        for i in range(start, 2 ** xmss.height):
            if not addr_state.ots_key_reuse(i):
                xmss.set_ots_index(i)
                return True
        return False

    def prepare_mining_xmss(self):
        if self._mining_xmss:
            if self._mining_xmss.ots_index < 2 ** config.user.random_mining_xmss_height:
                return self._mining_xmss

        self._mining_xmss = XMSS.from_height(config.user.random_mining_xmss_height)

        return self._mining_xmss

    def prepare_next_unmined_block_template(self, tx_pool, parent_block: Block, parent_difficulty):
        self.prepare_mining_xmss()

        try:
            self.cancel()
            self._mining_block = self.create_block(last_block=parent_block,
                                                   mining_nonce=0,
                                                   tx_pool=tx_pool,
                                                   signing_xmss=self._mining_xmss,
                                                   master_address=self._mining_credit_wallet)

            parent_metadata = self.state.get_block_metadata(parent_block.headerhash)
            self._measurement = self.state.get_measurement(self._mining_block.timestamp,
                                                           self._mining_block.prev_headerhash,
                                                           parent_metadata)

            self._current_difficulty, self._current_target = DifficultyTracker.get(
                measurement=self._measurement,
                parent_difficulty=parent_difficulty)

        except Exception as e:
            logger.warning("Exception in start_mining")
            logger.exception(e)

    def start_mining(self,
                     parent_block: Block,
                     parent_difficulty):

        self.prepare_mining_xmss()
        print("Before Mining Starts")
        self._mining_block.blockheader.debug()
        print("=====================")
        try:
            self.cancel()

            mining_blob = self._mining_block.mining_blob
            nonce_offset = self._mining_block.mining_nonce_offset

            logger.debug('!!! Mine #{} | {} ({}) | {} -> {} | {}'.format(
                self._mining_block.block_number,
                self._measurement, self._mining_block.timestamp - parent_block.timestamp,
                UInt256ToString(parent_difficulty), UInt256ToString(self._current_difficulty),
                self._current_target
            ))

            self.start(input=mining_blob,
                       nonceOffset=nonce_offset,
                       target=self._current_target,
                       thread_count=self._mining_thread_count)
        except Exception as e:
            logger.warning("Exception in start_mining")
            logger.exception(e)

    def solutionEvent(self, nonce):
        # NOTE: This function usually runs in the context of a C++ thread
        try:
            logger.debug('Solution Found %s', nonce)
            self._mining_block.set_mining_nonce(nonce)
            logger.info('Block #%s nonce: %s', self._mining_block.block_number, StringToUInt256(str(nonce))[-4:])
            logger.info('--->> %s', bin2hstr(self._mining_block.headerhash))
            print("When mining done")
            self._mining_block.blockheader.debug()
            print("=====================")

            logger.info('Hash Rate: %s H/s', self.hashRate())
            cloned_block = copy.deepcopy(self._mining_block)
            self.pre_block_logic(cloned_block)
        except Exception as e:
            logger.warning("Exception in solutionEvent")
            logger.exception(e)

    def create_block(self,
                     last_block,
                     mining_nonce,
                     tx_pool: TransactionPool,
                     signing_xmss,
                     master_address) -> Optional[Block]:
        # TODO: Persistence will move to rocksdb
        # FIXME: Difference between this and create block?????????????

        if (not self._dummy_xmss) or (self._dummy_xmss.ots_index == 2 ** self._dummy_xmss.height):
            self._dummy_xmss = XMSS.from_height(signing_xmss.height)

        dummy_block = Block.create(block_number=last_block.block_number + 1,
                                   prevblock_headerhash=last_block.headerhash,
                                   transactions=[],
                                   signing_xmss=self._dummy_xmss,
                                   master_address=master_address,
                                   nonce=0)
        dummy_block.set_mining_nonce(mining_nonce)

        t_pool2 = tx_pool.transactions

        total_txn = len(t_pool2)
        txnum = 0
        addresses_set = set()
        while txnum < total_txn:
            tx = t_pool2[txnum]
            tx.set_effected_address(addresses_set)
            txnum += 1

        addresses_state = dict()
        for address in addresses_set:
            addresses_state[address] = self.state.get_address(address)

        block_size = dummy_block.size
        block_size_limit = self.state.get_block_size_limit(last_block)
        txnum = 0
        while txnum < total_txn:
            tx = t_pool2[txnum]
            # Skip Transactions for later, which doesn't fit into block
            if block_size + tx.size + config.dev.tx_extra_overhead > block_size_limit:
                txnum += 1
                continue

            addr_from_pk_state = addresses_state[tx.addr_from]
            addr_from_pk = Transaction.get_slave(tx)
            if addr_from_pk:
                addr_from_pk_state = addresses_state[addr_from_pk]

            if addr_from_pk_state.ots_key_reuse(tx.ots_key):
                del t_pool2[txnum]
                total_txn -= 1
                continue

            if isinstance(tx, TransferTransaction):
                if addresses_state[tx.addr_from].balance < tx.total_amount + tx.fee:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.addr_from)
                    logger.warning('type: %s', tx.type)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s',
                                   addresses_state[tx.addr_from].balance,
                                   tx.total_amount)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            if isinstance(tx, MessageTransaction):
                if addresses_state[tx.addr_from].balance < tx.fee:
                    logger.warning('%s %s exceeds balance, invalid message tx', tx, tx.addr_from)
                    logger.warning('type: %s', tx.type)
                    logger.warning('Buffer State Balance: %s  Free %s', addresses_state[tx.addr_from].balance, tx.fee)
                    total_txn -= 1
                    continue

            if isinstance(tx, TokenTransaction):
                if addresses_state[tx.addr_from].balance < tx.fee:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.addr_from)
                    logger.warning('type: %s', tx.type)
                    logger.warning('Buffer State Balance: %s  Fee %s',
                                   addresses_state[tx.addr_from].balance,
                                   tx.fee)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            if isinstance(tx, TransferTokenTransaction):
                if addresses_state[tx.addr_from].balance < tx.fee:
                    logger.warning('%s %s exceeds balance, invalid tx', tx, tx.addr_from)
                    logger.warning('type: %s', tx.type)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s',
                                   addresses_state[tx.addr_from].balance,
                                   tx.fee)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                if bin2hstr(tx.token_txhash).encode() not in addresses_state[tx.addr_from].tokens:
                    logger.warning('%s doesnt own any token with token_txnhash %s', tx.addr_from,
                                   bin2hstr(tx.token_txhash).encode())
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

                if addresses_state[tx.addr_from].tokens[bin2hstr(tx.token_txhash).encode()] < tx.total_amount:
                    logger.warning('Token Transfer amount exceeds available token')
                    logger.warning('Token Txhash %s', bin2hstr(tx.token_txhash).encode())
                    logger.warning('Available Token Amount %s',
                                   addresses_state[tx.addr_from].tokens[bin2hstr(tx.token_txhash).encode()])
                    logger.warning('Transaction Amount %s', tx.total_amount)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            if isinstance(tx, LatticePublicKey):
                if addresses_state[tx.addr_from].balance < tx.fee:
                    logger.warning('Lattice TXN %s %s exceeds balance, invalid tx', tx, tx.addr_from)
                    logger.warning('type: %s', tx.type)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s',
                                   addresses_state[tx.addr_from].balance,
                                   tx.fee)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            if isinstance(tx, SlaveTransaction):
                if addresses_state[tx.addr_from].balance < tx.fee:
                    logger.warning('Slave TXN %s %s exceeds balance, invalid tx', tx, tx.addr_from)
                    logger.warning('type: %s', tx.type)
                    logger.warning('Buffer State Balance: %s  Transfer Amount %s',
                                   addresses_state[tx.addr_from].balance,
                                   tx.fee)
                    del t_pool2[txnum]
                    total_txn -= 1
                    continue

            tx.apply_on_state(addresses_state)

            tx._data.nonce = addr_from_pk_state.nonce
            txnum += 1
            block_size += tx.size + config.dev.tx_extra_overhead

        coinbase_nonce = self.state.get_address(signing_xmss.address).nonce
        if signing_xmss.address in addresses_state:
            coinbase_nonce = addresses_state[signing_xmss.address].nonce + 1

        block = Block.create(block_number=last_block.block_number + 1,
                             prevblock_headerhash=last_block.headerhash,
                             transactions=t_pool2,
                             signing_xmss=signing_xmss,
                             master_address=master_address,
                             nonce=coinbase_nonce)

        return block

    def get_block_to_mine(self, wallet_address) -> list:
        # TODO: use wallet_address to track the share
        if not self._mining_block:
            return []

        return [bin2hstr(self._mining_block.mining_blob),
                int(bin2hstr(self._current_difficulty), 16)]

    def submit_mined_block(self, blob) -> bool:
        if not self._mining_block.verify_blob(blob):
            return False

        blockheader = copy.deepcopy(self._mining_block.blockheader)
        blockheader.set_mining_nonce_from_blob(blob)

        if not PoWValidator().validate_mining_nonce(self.state, blockheader=blockheader):
            return False

        self._mining_block.set_mining_nonce(blockheader.mining_nonce)
        cloned_block = copy.deepcopy(self._mining_block)
        self.pre_block_logic(cloned_block)
        return True
