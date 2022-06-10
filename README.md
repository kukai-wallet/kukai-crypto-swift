# Kukai Crypto Swift

[![Platforms](https://img.shields.io/badge/Platforms-iOS%20%7C%20MacOS-blue)](https://img.shields.io/badge/Platforms-iOS%20%7C%20MacOS-blue)
[![Swift Package Manager](https://img.shields.io/badge/Swift_Package_Manager-compatible-orange)](https://img.shields.io/badge/Swift_Package_Manager-compatible-orange)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/kukai-wallet/kukai-crypto-swift/blob/main/LICENSE)


Kukai Crypto Swift is a native Swift library for creating regular and HD key pairs for the Tezos blockchain. Supporting both TZ1 (Ed25519) and TZ2 (secp256k1) for regular pairs, and TZ1 (Ed25519 ([BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) via [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md))) for HD pairs.

<br/>
Feature set includes:

- Create [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) mnemonics in English or Chinese
- Generate a cryptographic seed from a Menmonic in a tiny fraction of a second
- Create TZ1 or TZ2 key pair from a seed
- Derive HD key pair from a seed and derivation path
- Support for optional passwords


<br/>
Based off:

- [tezos-core-tools](https://github.com/tezos-commons/tezos-core-tools/blob/master/packages/crypto-utils/src/hd.ts)
- [WalletKit](https://github.com/KevinVitale/WalletKit)
- [TezosKit](https://github.com/keefertaylor/TezosKit)


<br/>
<br/>

# Install

Kukai Crypto Swift supports the Swift Package Manager. Either use the Xcode editor to add to your project by clicking `File` -> `Swift Packages` -> `Add Package Dependency`, search for the git repo `https://github.com/kukai-wallet/kukai-crypto-swift.git` and choose from version `1.0.0`.

Or add it to your `Package.swift` dependencies like so:

```
dependencies: [
    .package(url: "https://github.com/kukai-wallet/kukai-crypto-swift", from: "1.0.0")
]
```



<br/>
<br/>

# How to use

### Create a new Mnemonic

```Swift
let mnemonic = try Mnemonic(numberOfWords: .twentyFour)
```

### Create a Mnemonic from an existing phrase

```Swift
let mnemonic = try Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten inform")
```

### Create a regular key pair and get a Tezos address

```Swift
let keyPair = KeyPair.regular(fromMnemonic: mnemonic, passphrase: "", andSigningCurve: .ed25519)

print(keyPair.publicKey.publicKeyHash) // tz1T3QZ5w4K11RS3vy4TXiZepraV9R5GzsxG
```

```Swift
let keyPair = KeyPair.regular(fromMnemonic: mnemonic, passphrase: "", andSigningCurve: .secp256k1)

print(keyPair.publicKey.publicKeyHash) // tz2UiZQJwaVAKxRuYxV8Tx5k8a64gZx1ZwYJ

```

### Create a HD key pair

```Swift
let keyPair = KeyPair.hd(fromMnemonic: mnemonic, passphrase: "", andDerivationPath: "44'/1729'/0'/0'")
```


### Sign a message

```Swift
let messageToSign = "something very interesting that needs to be signed".bytes
let result = keyPair.privateKey.sign(bytes: messageToSign)

print("Result hex: \(result.hexString)") // c4d20c77d627d8c07e....
```



<br/>
<br/>

# Documentation

Compiled Swift Doc's can be found [here](https://kukai.app/kukai-crypto-swift/)

