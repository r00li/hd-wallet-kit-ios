import Foundation
import HSCryptoKit

public class HDWallet {
    private var publicKey: Data?
    private var seed: Data?
    private var keychain: HDKeychain?

    private var purpose: UInt32
    private var coinType: UInt32
    public var gapLimit: Int
    
    // MARK: - Kamino special additions
    // --------------------------------------------------------------------------------------------------------------------------------------------------------------------
    
    private(set) var isColdWallet: Bool = false
    private(set) var coldWalletXpub: HDPublicKey?
    
    public init(xpub: String, gapLimit: Int = 5) {
        self.gapLimit = gapLimit
        self.isColdWallet = true
        
        // When initializing a cold wallet this data is read from public key, so these values here don't matter.
        self.purpose = 44
        self.coinType = 0
        
        let decodedBase58 = HSCryptoKit.Base58.decode(xpub)
        
        if decodedBase58.count >= 81 {
            // xpub should be 81 bytes long
            
            let versionBytes = Data(decodedBase58[0...3])
            let depth = decodedBase58[4]
            let parentKeyFingerprint = Data(decodedBase58[5...8])
            let childNumber = Data(decodedBase58[9...12])
            let chainCode = Data(decodedBase58[13...44])
            let pubKey = Data(decodedBase58[45...77])
            
            var versionBytesUint32: UInt32 = 0
            (versionBytes as NSData).getBytes(&versionBytesUint32, length: MemoryLayout<UInt32>.size)
            
            var parentKeyFingerprintUint32: UInt32 = 0
            (parentKeyFingerprint as NSData).getBytes(&parentKeyFingerprintUint32, length: MemoryLayout<UInt32>.size)
            
            var childNumberUint32: UInt32 = 0
            (childNumber as NSData).getBytes(&childNumberUint32, length: MemoryLayout<UInt32>.size)
            
            self.coldWalletXpub = HDPublicKey(raw: pubKey, chainCode: chainCode, xPubKey: versionBytesUint32, depth: depth, fingerprint: parentKeyFingerprintUint32, childIndex: childNumberUint32)
        }
    }

    public init(seed: Data, coinType: UInt32, xPrivKey: UInt32, xPubKey: UInt32, gapLimit: Int = 5) {
        self.seed = seed
        self.gapLimit = gapLimit

        keychain = HDKeychain(seed: seed, xPrivKey: xPrivKey, xPubKey: xPubKey)
        purpose = 44
        self.coinType = coinType
    }
    
    // MARK: - End kamino additions
    // --------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public func privateKey(account: Int, index: Int, chain: Chain) throws -> HDPrivateKey {
        return try privateKey(path: "m/\(purpose)'/\(coinType)'/\(account)'/\(chain.rawValue)/\(index)")
    }

    public func privateKey(path: String) throws -> HDPrivateKey {
        guard let keychain = keychain else {
            throw NSError(domain: "RNS HD Wallet", code: 0, userInfo: nil)
        }
        
        let privateKey = try keychain.derivedKey(path: path)
        return privateKey
    }
    
    public func publicKey(account: Int, index: Int, chain: Chain) throws -> HDPublicKey {
        if isColdWallet {
            if let xpub = coldWalletXpub {
                return try xpub.derived(at: UInt32(account)).derived(at: UInt32(index))
            } else {
                throw NSError(domain: "RNS HD Wallet", code: 1, userInfo: nil)
            }
        } else {
            return try privateKey(account: account, index: index, chain: chain).publicKey()
        }
    }

    public enum Chain : Int {
        case external
        case `internal`
    }

}
