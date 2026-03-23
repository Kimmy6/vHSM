#include <botan/auto_rng.h>
#include <botan/base64.h>
#include <botan/data_src.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static std::string read_all_text(const std::string& path) {
   std::ifstream in(path, std::ios::binary);
   if(!in) {
      throw std::runtime_error("Failed to open file: " + path);
   }
   return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static void write_text_file(const std::string& path, const std::string& data) {
   std::ofstream out(path, std::ios::binary);
   if(!out) {
      throw std::runtime_error("Failed to open output file: " + path);
   }
   out << data;
}

int main() {
   try {
      Botan::AutoSeeded_RNG rng;

      // 1) 개인키 / 공개키 로드
      Botan::DataSource_Memory priv_src(read_all_text("mldsa_private.pem"));
      Botan::DataSource_Memory pub_src(read_all_text("mldsa_public.pem"));

      auto private_key = Botan::PKCS8::load_key(priv_src);
      auto public_key  = Botan::X509::load_key(pub_src);

      if(!private_key || !public_key) {
         throw std::runtime_error("Failed to load key(s).");
      }

      // 2) 서버가 challenge 생성
      std::vector<uint8_t> challenge(32);
      rng.randomize(challenge.data(), challenge.size());

      std::cout << "Challenge (hex): " << Botan::hex_encode(challenge) << "\n";

      // 3) 클라이언트가 개인키로 challenge 서명
      // ML-DSA는 해시/패딩이 알고리즘에 내장되어 있으므로 padding은 비워둘 수 있다.
      // 필요하면 "Deterministic" 또는 "Randomized"를 줄 수 있다.
      Botan::PK_Signer signer(*private_key, rng, "Randomized");
      auto signature = signer.sign_message(challenge, rng);

      const auto sig_b64 = Botan::base64_encode(signature);
      write_text_file("signature.b64", sig_b64);

      std::cout << "Signature written to signature.b64\n";

      // 4) 서버가 공개키로 검증
      Botan::PK_Verifier verifier(*public_key, "Randomized");
      const bool ok = verifier.verify_message(challenge, signature);

      std::cout << "Authentication result: " << (ok ? "SUCCESS" : "FAIL") << "\n";

      return ok ? 0 : 2;
   } catch(const std::exception& e) {
      std::cerr << "ERROR: " << e.what() << "\n";
      return 1;
   }
}