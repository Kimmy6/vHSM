#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/hmac_drbg.h>
#include <botan/mac.h>
#include <botan/pkcs8.h>
#include <botan/rng.h>
#include <botan/x509_key.h>
#include <botan/x509self.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

// [FIX] SeedThenSystemRNG 제거.
// 기존 구현은 32바이트 시드 소진 후 AutoSeeded_RNG(시스템 엔트로피)로 fallback해서
// ML-DSA-6x5 키 생성에 필요한 랜덤 바이트가 32바이트를 초과하면
// 시드만으로 키를 완전히 재현할 수 없었음.
//
// [NEW] HMAC_DRBG(SHA-256)으로 교체.
// 32바이트 시드를 DRBG에 주입하면 필요한 만큼의 랜덤 바이트를
// 결정론적으로 생성하므로 동일 시드 → 동일 키가 항상 보장됨.

static std::unique_ptr<Botan::RandomNumberGenerator> make_deterministic_rng(std::span<const uint8_t> seed32) {
   auto mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   auto drbg = std::make_unique<Botan::HMAC_DRBG>(std::move(mac));
   drbg->initialize_with(seed32.data(), seed32.size());
   return drbg;
}

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

static void print_usage(const char* argv0) {
   std::cerr << "Usage:\n"
             << "  " << argv0
             << " <seed_hex_file> <private_pem_out> <public_pem_out> <cert_pem_out> <subject_cn> [country] [organization]\n\n"
             << "Example:\n"
             << "  " << argv0 << " seed.hex hsm_priv.pem hsm_pub.pem hsm_cert.pem HSM-01 KR MyOrg\n";
}

int main(int argc, char* argv[]) {
   try {
      if(argc < 6 || argc > 8) {
         print_usage(argv[0]);
         return 1;
      }

      const std::string seed_file    = argv[1];
      const std::string private_out  = argv[2];
      const std::string public_out   = argv[3];
      const std::string cert_out     = argv[4];
      const std::string subject_cn   = argv[5];
      const std::string country      = (argc >= 7) ? argv[6] : "KR";
      const std::string organization = (argc >= 8) ? argv[7] : "VirtualHSM";

      const auto seed = read_seed_hex_file(seed_file);

      // [FIX] 키 생성에 HMAC_DRBG 사용 → 완전한 결정론적 키 생성 보장
      auto keygen_rng = make_deterministic_rng(seed);

      auto private_key = Botan::create_private_key("ML-DSA", *keygen_rng, "ML-DSA-6x5");
      if(!private_key) {
         throw std::runtime_error("ML-DSA key generation failed.");
      }

      auto public_key = private_key->public_key();
      if(!public_key) {
         throw std::runtime_error("Failed to derive public key.");
      }

      // 인증서 서명에는 시스템 RNG 사용 (서명은 결정론적일 필요 없음)
      Botan::AutoSeeded_RNG system_rng;

      Botan::X509_Cert_Options opts;
      opts.common_name   = subject_cn;
      opts.country       = country;
      opts.organization  = organization;
      opts.not_before("000101000000Z");
      opts.not_after("400101000000Z");

      auto cert = Botan::create_self_signed_cert(opts, *private_key, "", system_rng);

      write_text_file(private_out, Botan::PKCS8::PEM_encode(*private_key));
      write_text_file(public_out,  Botan::X509::PEM_encode(*public_key));
      write_text_file(cert_out,    cert.PEM_encode());

      std::cout << "Generated HSM ML-DSA identity\n";
      std::cout << "Private key : " << private_out << "\n";
      std::cout << "Public key  : " << public_out  << "\n";
      std::cout << "Certificate : " << cert_out    << "\n";
      std::cout << "Subject CN  : " << subject_cn  << "\n";
      std::cout << "Seed (hex)  : " << Botan::hex_encode(seed) << "\n";

      return 0;
   } catch(const std::exception& e) {
      std::cerr << "ERROR: " << e.what() << "\n";
      return 1;
   }
}
