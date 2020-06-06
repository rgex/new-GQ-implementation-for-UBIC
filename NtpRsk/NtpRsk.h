#ifndef NTPESK_NTPRSK_H
#define NTPESK_NTPRSK_H

#include "NtpRskSignatureVerificationObject.h"
#include "NtpRskSignatureRequestObject.h"

class NtpRsk {
    public:
        static NtpRskSignatureVerificationObject *signWithNtpRsk(NtpRskSignatureRequestObject *ntpEskSignatureRequestObject);
        static bool verifyNtpRsk(NtpRskSignatureVerificationObject *ntpEskSignatureVerificationObject);
        static std::vector<unsigned char> concatCharVector(std::vector<unsigned char> path1, std::vector<unsigned char> path2);
        static std::vector<unsigned char> concatCharVector(std::vector<unsigned char> path1, const char* path2);
        static std::vector<unsigned char> concatCharVector(const char* path1, const char* path2);
    private:
        static BIGNUM* randomBignum(const BIGNUM* maxSize);
};


#endif //NTPESK_NTPRSK_H
