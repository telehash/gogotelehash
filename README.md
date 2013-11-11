gogotelehash
============

TODO:

- close channels properly
- better ACK
- Kademlia DHT

[Changes since implementation](https://github.com/telehash/telehash.org/compare/feb3421b36a03e97f395f014a494f5dc90695f04...master)


# Channel termination

When a peer sends an `end` packet it can no longer send new packets or
  receive any packets (even if they were already buffered). The sender must still
  handle ack packets to make sure the receiver receives all missing packets (including the last one.)

When a peer receives and  `end` packet it can no longer send new packets
