#include <iostream>
#include <ossl_typ.h>
#include <rsa.h>
#include <obj_mac.h>
#include <sha.h>
#include <evp.h>
#include "NtpRsk/NtpRsk.h"
#include "Tools/Hexdump.h"
#include "Crypto/ECCtools.h"

void sha256_string(char *string, unsigned char *hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
}

int main() {

    unsigned char passportHash[SHA256_DIGEST_LENGTH];
    sha256_string("Passport data", passportHash);


    unsigned char messageHash[SHA256_DIGEST_LENGTH];
    sha256_string("Signed message", messageHash);

    RSA *rsa = RSA_generate_key(512, 65537, 0, 0); //key length: 2048 bits, exponent: 65537

    unsigned char sigret[2048/8];
    unsigned int siglen;


    if(RSA_sign(NID_sha256, messageHash, SHA256_DIGEST_LENGTH, sigret, &siglen, rsa) != 1) {
        return 0;
    }

    std::cout << "messageHash: " << Hexdump::ucharToHexString(messageHash, SHA256_DIGEST_LENGTH) << std::endl;

    unsigned char decrypt_buf[4096];

    int decryptedLen = RSA_public_decrypt((int)siglen, sigret, decrypt_buf, rsa,
                                 RSA_NO_PADDING);

    const BIGNUM *n = BN_new();
    const BIGNUM *e = BN_new();
    RSA_get0_key(rsa, &n, &e, nullptr);

    std::cout << "n: " << BN_bn2hex(n) << std::endl;
    std::cout << "e (dec): " << BN_bn2dec(e) << std::endl;

    NtpRskSignatureRequestObject ntpRskSignatureRequestObject;
    ntpRskSignatureRequestObject.setN(n);
    ntpRskSignatureRequestObject.setE(e);
    ntpRskSignatureRequestObject.setNm(std::vector<unsigned char>(messageHash, messageHash + (int)SHA256_DIGEST_LENGTH));
    ntpRskSignatureRequestObject.setVersion(6);
    ntpRskSignatureRequestObject.setM(BN_bin2bn(passportHash, (int)SHA256_DIGEST_LENGTH, NULL));

    ntpRskSignatureRequestObject.setPaddedM(
            ECCtools::vectorToBn(std::vector<unsigned char>(decrypt_buf, decrypt_buf + (int)decryptedLen))
            );
    ntpRskSignatureRequestObject.setSignature(ECCtools::vectorToBn(
            std::vector<unsigned char>(sigret, sigret + (int)siglen)
            ));

    NtpRskSignatureVerificationObject* ntpRskSignatureVerificationObject = NtpRsk::signWithNtpRsk(&ntpRskSignatureRequestObject);

    if(NtpRsk::verifyNtpRsk(ntpRskSignatureVerificationObject)) {
        std::cout << "Verification succeeded" << std::endl;
    } else {
        std::cout << "Verification failed" << std::endl;
    }

    return 0;
}
