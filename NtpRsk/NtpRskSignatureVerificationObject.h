#include <vector>

#ifndef NTPESK_NTPRSKSIGNATUREVERIFICATIONOBJECT_H
#define NTPESK_NTPRSKSIGNATUREVERIFICATIONOBJECT_H

#endif //NTPESK_NTPRSKSIGNATUREVERIFICATIONOBJECT_H

class NtpRskSignatureVerificationObject {
private:
    uint8_t version = 6;
    const BIGNUM* e;
    const BIGNUM* n;
    BIGNUM* T;
    BIGNUM* t1;
    BIGNUM* t2;
    BIGNUM* t3;
    BIGNUM* t4;
    BIGNUM* t5;
    BIGNUM* t6;
    BIGNUM* t7;
    BIGNUM* t8;
    BIGNUM* m;
    BIGNUM* paddedM;
    BIGNUM* nm;
    std::vector<unsigned char> nmVector;
    std::vector<unsigned char> m2;
    uint16_t mdAlg;
    std::vector<unsigned char> signedPayload;
public:
    const BIGNUM *getE() const {
        return this->e;
    }

    void setE(const BIGNUM *e) {
        this->e = e;
    }

    const BIGNUM *getN() const {
        return this->n;
    }

    void setN(const BIGNUM *n) {
        this->n = n;
    }

    BIGNUM *getT() const {
        return this->T;
    }

    void setT(BIGNUM *T) {
        this->T = T;
    }

    BIGNUM *getT1() const {
        return this->t1;
    }

    void setT1(BIGNUM *t1) {
        this->t1 = t1;
    }

    BIGNUM *getT2() const {
        return this->t2;
    }

    void setT2(BIGNUM *t2) {
        this->t2 = t2;
    }

    BIGNUM *getT3() const {
        return t3;
    }

    void setT3(BIGNUM *t3) {
        this->t3 = t3;
    }

    BIGNUM *getT4() const {
        return this->t4;
    }

    void setT4(BIGNUM *t4) {
        this->t4 = t4;
    }

    BIGNUM *getT5() const {
        return this->t5;
    }

    void setT5(BIGNUM *t5) {
        this->t5 = t5;
    }

    BIGNUM *getT6() const {
        return t6;
    }

    void setT6(BIGNUM *t6) {
        NtpRskSignatureVerificationObject::t6 = t6;
    }

    BIGNUM *getT7() const {
        return t7;
    }

    void setT7(BIGNUM *t7) {
        NtpRskSignatureVerificationObject::t7 = t7;
    }

    BIGNUM *getT8() const {
        return t8;
    }

    void setT8(BIGNUM *t8) {
        NtpRskSignatureVerificationObject::t8 = t8;
    }

    std::vector<unsigned char> getM2() const {
        return m2;
    }

    void setM2(std::vector<unsigned char> m2) {
        NtpRskSignatureVerificationObject::m2 = m2;
    }


    BIGNUM *getPaddedM() {
        return paddedM;
    }

    void setPaddedM(BIGNUM *paddedM) {
        this->paddedM = paddedM;
    }

    BIGNUM *getM() const {
        return this->m;
    }

    void setM(BIGNUM *m) {
        this->m = m;
    }

    BIGNUM *getNm() const {
        return this->nm;
    }

    void setNm(BIGNUM *nm) {
        this->nm = nm;
    }

    const std::vector<unsigned char> &getNmVector() const {
        return nmVector;
    }

    void setNmVector(const std::vector<unsigned char> &nmVector) {
        NtpRskSignatureVerificationObject::nmVector = nmVector;
    }

    uint8_t getVersion() const {
        return version;
    }

    void setVersion(uint8_t version) {
        NtpRskSignatureVerificationObject::version = version;
    }

    uint16_t getMdAlg() const {
        return mdAlg;
    }

    void setMdAlg(uint16_t mdAlg) {
        NtpRskSignatureVerificationObject::mdAlg = mdAlg;
    }

    const std::vector<unsigned char> &getSignedPayload() const {
        return signedPayload;
    }

    void setSignedPayload(const std::vector<unsigned char> &signedPayload) {
        NtpRskSignatureVerificationObject::signedPayload = signedPayload;
    }
};
