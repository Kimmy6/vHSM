#include "MldsaService.h"

#include "FileUtils.h"

#include <botan/auto_rng.h>
#include <botan/data_src.h>
#include <botan/pk_algs.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>

#include <vector>

bool MldsaService::generateDeviceKeyPair(const QString &privateKeyPath,
                                         const QString &publicKeyPath,
                                         QString *publicKeyPem,
                                         QString *errorMessage) const
{
    try {
        Botan::AutoSeeded_RNG rng;
        auto privateKey = Botan::create_private_key("ML-DSA", rng, "ML-DSA-6x5");
        if (!privateKey) {
            if (errorMessage)
                *errorMessage = QStringLiteral("ML-DSA 키 생성에 실패했습니다.");
            return false;
        }

        auto publicKey = privateKey->public_key();
        const QString privatePem = QString::fromStdString(Botan::PKCS8::PEM_encode(*privateKey));
        const QString publicPemText = QString::fromStdString(Botan::X509::PEM_encode(*publicKey));

        QString fileError;
        if (!FileUtils::writeTextFile(privateKeyPath, privatePem, &fileError)) {
            if (errorMessage)
                *errorMessage = fileError;
            return false;
        }

        if (!FileUtils::writeTextFile(publicKeyPath, publicPemText, &fileError)) {
            if (errorMessage)
                *errorMessage = fileError;
            return false;
        }

        if (publicKeyPem)
            *publicKeyPem = publicPemText;
        if (errorMessage)
            errorMessage->clear();
        return true;
    } catch (const std::exception &e) {
        if (errorMessage)
            *errorMessage = QStringLiteral("ML-DSA 키 생성에 실패했습니다.");
        return false;
    }
}

bool MldsaService::signMessage(const QString &privateKeyPem,
                               const QByteArray &message,
                               QByteArray *signature,
                               QString *errorMessage) const
{
    try {
        Botan::AutoSeeded_RNG rng;
        Botan::DataSource_Memory privateSrc(privateKeyPem.toStdString());
        auto privateKey = Botan::PKCS8::load_key(privateSrc);
        if (!privateKey) {
            if (errorMessage)
                *errorMessage = QStringLiteral("스마트폰 개인키를 불러오지 못했습니다.");
            return false;
        }

        Botan::PK_Signer signer(*privateKey, rng, "Randomized");
        const std::vector<uint8_t> messageBytes(message.begin(), message.end());
        const auto sig = signer.sign_message(messageBytes, rng);

        if (signature)
            *signature = QByteArray(reinterpret_cast<const char *>(sig.data()), static_cast<int>(sig.size()));
        if (errorMessage)
            errorMessage->clear();
        return true;
    } catch (const std::exception &e) {
        if (errorMessage)
            *errorMessage = QStringLiteral("스마트폰 서명 생성에 실패했습니다.");
        return false;
    }
}

bool MldsaService::verifyMessage(const QString &publicKeyPem,
                                 const QByteArray &message,
                                 const QByteArray &signature,
                                 QString *errorMessage) const
{
    try {
        Botan::DataSource_Memory publicSrc(publicKeyPem.toStdString());
        auto publicKey = Botan::X509::load_key(publicSrc);
        if (!publicKey) {
            if (errorMessage)
                *errorMessage = QStringLiteral("공개키를 불러오지 못했습니다.");
            return false;
        }

        Botan::PK_Verifier verifier(*publicKey, "");
        const std::vector<uint8_t> messageBytes(message.begin(), message.end());
        const std::vector<uint8_t> signatureBytes(signature.begin(), signature.end());
        const bool ok = verifier.verify_message(messageBytes, signatureBytes);

        if (!ok && errorMessage)
            *errorMessage = QStringLiteral("서명 검증에 실패했습니다.");
        else if (errorMessage)
            errorMessage->clear();
        return ok;
    } catch (const std::exception &e) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Pi 서명 검증에 실패했습니다.");
        return false;
    }
}
