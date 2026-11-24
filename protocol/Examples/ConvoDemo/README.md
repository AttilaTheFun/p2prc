# ConvoDemo

The smallest client that exercises the protocol end to end: identity and
KeyPackage, the genesis handshake through a node's rendezvous boxes, messages
through the hosts, and audio/video calls on a data channel to the peer
(Part III §22–§25). Plain SwiftUI, iOS and macOS, one file.

```sh
swift run convo_node --no-relay     # a node on :8080 (or point at a real one)
cd Examples/ConvoDemo && xcodegen && open ConvoDemo.xcodeproj
```

Run two copies (a Mac and a phone, or two Macs), connect both to the same
node, paste one identity into the other's "peer identity" and press Create,
paste the salt into the first and press Join. A lone node has no
witnesses, so its checkpoints are never published and messages stay `sent`;
run three nodes that witness one another (`--witness URL`) to see them
commit.
