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

int main(int argc, char* argv[]) {
   try {
      if(argc != 3) {
         std::cerr << "Usage: " << argv[0] << " <private_pem> <public_pem>\n";
         return 1;
      }

      const std::string private_path = argv[1];
      const std::string public_path = argv[2];

      Botan::AutoSeeded_RNG rng;

      Botan::DataSource_Memory priv_src(read_all_text(private_path));
      Botan::DataSource_Memory pub_src(read_all_text(public_path));

      auto private_key = Botan::PKCS8::load_key(priv_src);
      auto public_key = Botan::X509::load_key(pub_src);

      if(!private_key || !public_key) {
         throw std::runtime_error("Failed to load key(s).");
      }

      std::vector<uint8_t> challenge(32);
      rng.randomize(challenge.data(), challenge.size());

      Botan::PK_Signer signer(*private_key, rng, "Randomized");
      auto signature = signer.sign_message(challenge, rng);

      const auto sig_b64 = Botan::base64_encode(signature);
      write_text_file("signature.b64", sig_b64);

      Botan::PK_Verifier verifier(*public_key, "");
      const bool ok = verifier.verify_message(challenge, signature);

      std::cout << "Authentication result: " << (ok ? "SUCCESS" : "FAIL") << "\n";
      return ok ? 0 : 2;
   } catch(const std::exception& e) {
      std::cerr << "ERROR: " << e.what() << "\n";
      return 1;
   }
}