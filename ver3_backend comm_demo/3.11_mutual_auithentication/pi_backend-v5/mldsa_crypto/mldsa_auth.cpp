#include <botan/auto_rng.h>
#include <botan/base64.h>
#include <botan/data_src.h>
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

static std::vector<uint8_t> decode_b64(const std::string& b64) {
   const auto decoded = Botan::base64_decode(b64);
   return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

int main(int argc, char* argv[]) {
   try {
      if(argc < 2) {
         std::cerr << "Usage:\n"
                   << "  " << argv[0] << " sign <private_pem> <message_b64>\n"
                   << "  " << argv[0] << " verify <public_pem> <message_b64> <signature_b64>\n";
         return 1;
      }

      const std::string mode = argv[1];
      Botan::AutoSeeded_RNG rng;

      if(mode == "sign") {
         if(argc != 4) {
            std::cerr << "Usage: " << argv[0] << " sign <private_pem> <message_b64>\n";
            return 1;
         }

         Botan::DataSource_Memory priv_src(read_all_text(argv[2]));
         auto private_key = Botan::PKCS8::load_key(priv_src);
         if(!private_key) {
            throw std::runtime_error("Failed to load private key.");
         }

         const auto message = decode_b64(argv[3]);
         Botan::PK_Signer signer(*private_key, rng, "Randomized");
         const auto signature = signer.sign_message(message, rng);

         std::cout << "SIG_BASE64:" << Botan::base64_encode(signature) << "\n";
         return 0;
      }

      if(mode == "verify") {
         if(argc != 5) {
            std::cerr << "Usage: " << argv[0] << " verify <public_pem> <message_b64> <signature_b64>\n";
            return 1;
         }

         Botan::DataSource_Memory pub_src(read_all_text(argv[2]));
         auto public_key = Botan::X509::load_key(pub_src);
         if(!public_key) {
            throw std::runtime_error("Failed to load public key.");
         }

         const auto message = decode_b64(argv[3]);
         const auto signature = decode_b64(argv[4]);

         Botan::PK_Verifier verifier(*public_key, "Randomized");
         const bool ok = verifier.verify_message(message, signature);

         std::cout << (ok ? "OK" : "FAIL") << "\n";
         return ok ? 0 : 2;
      }

      throw std::runtime_error("Unknown mode: " + mode);
   } catch(const std::exception& e) {
      std::cerr << "ERROR: " << e.what() << "\n";
      return 1;
   }
}