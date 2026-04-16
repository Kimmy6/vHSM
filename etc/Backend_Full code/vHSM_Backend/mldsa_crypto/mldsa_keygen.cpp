#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pk_algs.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/rng.h>

#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

// 첫 32바이트는 사용자가 넣은 seed를 그대로 내보내고,
// 그 이후 추가로 랜덤이 더 필요하면 fallback RNG로 넘기는 래퍼.
// Botan 테스트 코드의 Fixed_Output_RNG 패턴을 참고한 형태다.
class SeedThenSystemRNG final : public Botan::RandomNumberGenerator {
   public:
      SeedThenSystemRNG(std::span<const uint8_t> seed32, Botan::RandomNumberGenerator& fallback) :
         m_buf(seed32.begin(), seed32.end()), m_fallback(fallback) {}

      bool is_seeded() const override { return true; }

      bool accepts_input() const override { return true; }

      std::string name() const override { return "SeedThenSystemRNG"; }

      void clear() noexcept override {}

   protected:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override {
         // 외부 입력 entropy가 들어오면 버퍼 뒤에 붙인다.
         m_buf.insert(m_buf.end(), input.begin(), input.end());

         for(auto& b : output) {
            if(m_pos < m_buf.size()) {
               b = m_buf[m_pos++];
            } else {
               m_fallback.randomize(&b, 1);
            }
         }
      }

   private:
      std::vector<uint8_t> m_buf;
      size_t m_pos = 0;
      Botan::RandomNumberGenerator& m_fallback;
};

static std::vector<uint8_t> read_seed_hex_file(const std::string& path) {
   std::ifstream in(path);
   if(!in) {
      throw std::runtime_error("Failed to open seed file: " + path);
   }

   std::string hex;
   in >> hex;
   auto seed = Botan::hex_decode(hex);

   if(seed.size() != 32) {
      throw std::runtime_error("Seed must be exactly 32 bytes (64 hex chars).");
   }

   return seed;
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
      if(argc != 2) {
         std::cerr << "Usage: " << argv[0] << " <seed_hex_file>\n";
         std::cerr << "Example seed file content: 64 hex chars (=32 bytes)\n";
         return 1;
      }

      const std::string seed_file = argv[1];
      const auto seed = read_seed_hex_file(seed_file);

      Botan::AutoSeeded_RNG system_rng;
      SeedThenSystemRNG keygen_rng(seed, system_rng);

      // Botan 버전에 따라 ML-DSA-65 대신 ML-DSA-6x5가 필요할 수 있음.
      const std::string params = "ML-DSA-6x5";

      auto private_key = Botan::create_private_key("ML-DSA", keygen_rng, params);
      if(!private_key) {
         throw std::runtime_error("ML-DSA key generation failed.");
      }

      auto public_key = private_key->public_key();

      // PEM 저장
      write_text_file("mldsa_private.pem", Botan::PKCS8::PEM_encode(*private_key));
      write_text_file("mldsa_public.pem", Botan::X509::PEM_encode(*public_key));

      std::cout << "Generated ML-DSA key pair\n";
      std::cout << "Private key: mldsa_private.pem\n";
      std::cout << "Public key : mldsa_public.pem\n";
      std::cout << "Seed (hex) : " << Botan::hex_encode(seed) << "\n";

      return 0;
   } catch(const std::exception& e) {
      std::cerr << "ERROR: " << e.what() << "\n";
      return 1;
   }
}