# Iteracting with contract using NEAR CLI
All data is fake and used for example purposes
It's necessary to update script after contract API changes
## User contract API

near call v1.signer-dev.testnet sign '{"request":{"key_version":0,"path":"test","payload":[12,1,2,0,4,5,6,8,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,44]}}' --accountId alexkushnir.testnet --gas 300000000000000 --deposit 1

near view v1.signer-dev.testnet public_key

near view v1.signer-dev.testnet derived_public_key {"path":"test","predecessor":"alexkushnir.testnet"}

near view v1.signer-dev.testnet latest_key_version

near view v1.signer-dev.testnet experimental_signature_deposit


## Node API

near call v1.signer-dev.testnet respond '{"request":{"epsilon":{"scalar":"72DB59A313FA266B1C3B40F20325C9023DDC564E7790363BCC2AE76580339648"},"payload_hash":{"scalar":"05FCB4470106774DCC5A3C7689FD2917C15AB81B6FA44960843E6389780A5364"}},"response":{"big_r":{"affine_point":"02EC7FA686BB430A4B700BDA07F2E07D6333D9E33AEEF270334EB2D00D0A6FEC6C"},"recovery_id":0,"s":{"scalar":"20F90C540EE00133C911EA2A9ADE2ABBCC7AD820687F75E011DFEEC94DB10CD6"}}}' --accountId alexkushnir.testnet --gas 300000000000000

near call v1.signer-dev.testnet join '{"cipher_pk":[59,105,187,93,147,173,85,119,242,237,171,117,87,221,135,181,28,120,239,58,50,198,137,77,219,16,151,195,93,140,92,88],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"http://localhost:3030"}' --accountId alexkushnir.testnet --gas 300000000000000

near call v1.signer-dev.testnet vote_join '{"candidate":"alexkushnir.testnet"}' --accountId alexkushnir.testnet --gas 300000000000000

near call v1.signer-dev.testnet vote_leave '{"kick":"alexkushnir.testnet"}' --accountId alexkushnir.testnet --gas 300000000000000

near call v1.signer-dev.testnet vote_pk '{"public_key": ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae}' --accountId alexkushnir.testnet --gas 300000000000000

near call v1.signer-dev.testnet vote_reshared '{"epoch": 1}' --accountId alexkushnir.testnet --gas 300000000000000

near call v1.signer-dev.testnet propose_update --base64 "AAHgkwQAAAAAAADdbQAAAAAAAgAAAEAAAAAABAAAAABAAMAnCQAAAAAAAAAAAAACAAAAACAAyK8AAAAAAAAAAAAAyK8AAAAAAABADQMAAAAAAABcJgUAAAAAAAAAAAAAAAAAAAAA" --accountId alexkushnir.testnet --gas 300000000000000

near call v1.signer-dev.testnet vote_update '{"id": 0}' --accountId alexkushnir.testnet --gas 300000000000000


## Contract developer helper API

near call v1.signer-dev.testnet init '{"candidates":{"candidates":{"alice.near":{"account_id":"alice.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"},"bob.near":{"account_id":"bob.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"},"caesar.near":{"account_id":"caesar.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"}}},"threshold":1}' --accountId alexkushnir.testnet --gas 300000000000000

near call v1.signer-dev.testnet init_running '{"epoch":0,"participants":{"account_to_participant_id":{"alice.near":0,"bob.near":1,"caesar.near":2},"next_id":3,"participants":{"alice.near":{"account_id":"alice.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"},"bob.near":{"account_id":"bob.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"},"caesar.near":{"account_id":"caesar.near","cipher_pk":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sign_pk":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","url":"127.0.0.1"}}},"public_key":"ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae","threshold":2}' --accountId alexkushnir.testnet --gas 300000000000000

near view v1.signer-dev.testnet migrate

near view v1.signer-dev.testnet state

near view v1.signer-dev.testnet config

near view v1.signer-dev.testnet version

