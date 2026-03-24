#include <botan/auto_rng.h>
#include <botan/base64.h>
#include <botan/data_src.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/ocsp.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/tls.h>
#include <botan/x509_key.h>
#include <botan/x509cert.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>       // [FIX] 멀티스레드 처리
#include <vector>

namespace {

constexpr std::string_view kBindingLabel   = "EXPERIMENTAL-vHSM-auth-binding";
constexpr std::string_view kBindingContext = "vHSM-MLDSA-AUTH-V1";
constexpr size_t kExporterBytes  = 32;
constexpr size_t kSocketReadBuf  = 16 * 1024;
constexpr int    kSocketTimeoutSec = 30;   // [FIX] 소켓 타임아웃 상수

// ─────────────────────────────────────────────
// 파일 I/O 헬퍼
// ─────────────────────────────────────────────

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

// ─────────────────────────────────────────────
// 소켓 헬퍼
// ─────────────────────────────────────────────

// [FIX] 소켓 송수신 타임아웃 설정.
// 악의적인 클라이언트가 연결만 맺고 데이터를 보내지 않으면
// recv()가 영구 블록되는 문제를 방지함.
static void set_socket_timeout(int fd, int seconds) {
   struct timeval tv{};
   tv.tv_sec  = seconds;
   tv.tv_usec = 0;
   ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
   ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static std::vector<uint8_t> to_bytes(std::string_view s) {
   return std::vector<uint8_t>(s.begin(), s.end());
}

static std::vector<uint8_t> decode_b64(const std::string& b64) {
   const auto decoded = Botan::base64_decode(b64);
   return std::vector<uint8_t>(decoded.begin(), decoded.end());
}

static std::string encode_b64(std::span<const uint8_t> data) {
   return Botan::base64_encode(data.data(), data.size());
}

static std::string sha256_hex(std::span<const uint8_t> data) {
   auto hash = Botan::HashFunction::create_or_throw("SHA-256");
   hash->update(data);
   return Botan::hex_encode(hash->final());
}

// ─────────────────────────────────────────────
// 키 / 인증서 로더
// ─────────────────────────────────────────────

static std::unique_ptr<Botan::Private_Key> load_private_key_from_pem(const std::string& path) {
   Botan::DataSource_Memory src(read_all_text(path));
   auto key = Botan::PKCS8::load_key(src);
   if(!key) {
      throw std::runtime_error("Failed to load private key from: " + path);
   }
   return key;
}

static Botan::X509_Certificate load_certificate_from_pem_file(const std::string& path) {
   Botan::DataSource_Memory src(read_all_text(path));
   return Botan::X509_Certificate(src);
}

static Botan::X509_Certificate load_certificate_from_pem_string(const std::string& pem) {
   Botan::DataSource_Memory src(pem);
   return Botan::X509_Certificate(src);
}

static std::string cert_sha256_hex(const Botan::X509_Certificate& cert) {
   return sha256_hex(cert.BER_encode());
}

// ─────────────────────────────────────────────
// 서명 페이로드 구성
// ─────────────────────────────────────────────

static std::vector<uint8_t> make_signed_payload(std::span<const uint8_t> nonce,
                                                std::span<const uint8_t> exporter) {
   std::vector<uint8_t> payload;
   payload.reserve(kBindingContext.size() + 1 + nonce.size() + exporter.size());
   payload.insert(payload.end(), kBindingContext.begin(), kBindingContext.end());
   payload.push_back(0x00);
   payload.insert(payload.end(), nonce.begin(), nonce.end());
   payload.insert(payload.end(), exporter.begin(), exporter.end());
   return payload;
}

// ─────────────────────────────────────────────
// 네트워크 헬퍼
// ─────────────────────────────────────────────

static void send_all(int fd, std::span<const uint8_t> data) {
   size_t sent = 0;
   while(sent < data.size()) {
      const auto rc = ::send(fd, data.data() + sent, data.size() - sent, 0);
      if(rc < 0) {
         throw std::runtime_error(std::string("send() failed: ") + std::strerror(errno));
      }
      sent += static_cast<size_t>(rc);
   }
}

static int connect_tcp(const std::string& ip, uint16_t port) {
   const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
   if(fd < 0) {
      throw std::runtime_error(std::string("socket() failed: ") + std::strerror(errno));
   }

   sockaddr_in addr{};
   addr.sin_family = AF_INET;
   addr.sin_port   = htons(port);
   if(::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
      ::close(fd);
      throw std::runtime_error("Invalid IPv4 address: " + ip);
   }

   if(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      const auto msg = std::string("connect() failed: ") + std::strerror(errno);
      ::close(fd);
      throw std::runtime_error(msg);
   }

   return fd;
}

static int create_listen_socket(uint16_t port) {
   const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
   if(fd < 0) {
      throw std::runtime_error(std::string("socket() failed: ") + std::strerror(errno));
   }

   const int enable = 1;
   ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

   sockaddr_in addr{};
   addr.sin_family      = AF_INET;
   addr.sin_addr.s_addr = htonl(INADDR_ANY);
   addr.sin_port        = htons(port);

   if(::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      const auto msg = std::string("bind() failed: ") + std::strerror(errno);
      ::close(fd);
      throw std::runtime_error(msg);
   }

   if(::listen(fd, 8) != 0) {
      const auto msg = std::string("listen() failed: ") + std::strerror(errno);
      ::close(fd);
      throw std::runtime_error(msg);
   }

   return fd;
}

// ─────────────────────────────────────────────
// TLS 정책 / 크레덴셜
// ─────────────────────────────────────────────

class TLS13OnlyPolicy final : public Botan::TLS::Policy {
   public:
      bool allow_tls12() const override { return false; }
      bool allow_tls13() const override { return true; }
      bool require_cert_revocation_info() const override { return false; }
};

class ServerCredentials final : public Botan::Credentials_Manager {
   public:
      ServerCredentials(const std::string& tls_cert_pem, const std::string& tls_key_pem) :
         m_cert(load_certificate_from_pem_file(tls_cert_pem)) {
         Botan::DataSource_Memory src(read_all_text(tls_key_pem));
         auto key = Botan::PKCS8::load_key(src);
         if(!key) {
            throw std::runtime_error("Failed to load TLS private key: " + tls_key_pem);
         }
         m_key.reset(key.release());
      }

      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
         [[maybe_unused]] const std::string& type,
         [[maybe_unused]] const std::string& context) override {
         return {};
      }

      std::vector<Botan::X509_Certificate> cert_chain(
         [[maybe_unused]] const std::vector<std::string>& cert_key_types,
         [[maybe_unused]] const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
         [[maybe_unused]] const std::string& type,
         [[maybe_unused]] const std::string& context) override {
         return {m_cert};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(
         [[maybe_unused]] const Botan::X509_Certificate& cert,
         [[maybe_unused]] const std::string& type,
         [[maybe_unused]] const std::string& context) override {
         return m_key;
      }

   private:
      Botan::X509_Certificate              m_cert;
      std::shared_ptr<Botan::Private_Key>  m_key;
};

class ClientCredentials final : public Botan::Credentials_Manager {
   public:
      std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
         [[maybe_unused]] const std::string& type,
         [[maybe_unused]] const std::string& context) override {
         return {};
      }

      std::vector<Botan::X509_Certificate> cert_chain(
         [[maybe_unused]] const std::vector<std::string>& cert_key_types,
         [[maybe_unused]] const std::vector<Botan::AlgorithmIdentifier>& cert_signature_schemes,
         [[maybe_unused]] const std::string& type,
         [[maybe_unused]] const std::string& context) override {
         return {};
      }

      std::shared_ptr<Botan::Private_Key> private_key_for(
         [[maybe_unused]] const Botan::X509_Certificate& cert,
         [[maybe_unused]] const std::string& type,
         [[maybe_unused]] const std::string& context) override {
         return nullptr;
      }
};

// ─────────────────────────────────────────────
// TLS 콜백 / 채널 헬퍼
// ─────────────────────────────────────────────

class SocketTLSCallbacks : public Botan::TLS::Callbacks {
   public:
      explicit SocketTLSCallbacks(int fd) : m_fd(fd) {}

      void tls_emit_data(std::span<const uint8_t> data) override { send_all(m_fd, data); }

      void tls_record_received([[maybe_unused]] uint64_t seq_no,
                               std::span<const uint8_t> data) override {
         m_app_buffer.append(reinterpret_cast<const char*>(data.data()), data.size());
      }

      void tls_alert(Botan::TLS::Alert alert) override {
         if(alert.is_valid()) {
            std::cerr << "[TLS ALERT] " << alert.type_string();
            if(alert.is_fatal()) { std::cerr << " (fatal)"; }
            std::cerr << "\n";
         }
      }

      void tls_session_established(
         [[maybe_unused]] const Botan::TLS::Session_Summary& session) override {
         m_established = true;
      }

      // 전송 레이어 인증서 검증 생략 - 애플리케이션 레이어에서 ML-DSA pinned cert로 검증함
      void tls_verify_cert_chain(
         [[maybe_unused]] const std::vector<Botan::X509_Certificate>& cert_chain,
         [[maybe_unused]] const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp_responses,
         [[maybe_unused]] const std::vector<Botan::Certificate_Store*>& trusted_roots,
         [[maybe_unused]] Botan::Usage_Type usage,
         [[maybe_unused]] std::string_view hostname,
         [[maybe_unused]] const Botan::TLS::Policy& policy) override {}

      bool established() const { return m_established; }
      bool has_complete_line() const { return m_app_buffer.find('\n') != std::string::npos; }

      std::string pop_line() {
         const auto pos = m_app_buffer.find('\n');
         if(pos == std::string::npos) {
            throw std::runtime_error("No complete application line available.");
         }
         std::string line = m_app_buffer.substr(0, pos);
         m_app_buffer.erase(0, pos + 1);
         if(!line.empty() && line.back() == '\r') { line.pop_back(); }
         return line;
      }

   private:
      int         m_fd;
      bool        m_established = false;
      std::string m_app_buffer;
};

static void recv_and_feed(int fd, Botan::TLS::Channel& channel) {
   std::vector<uint8_t> buf(kSocketReadBuf);
   const auto rc = ::recv(fd, buf.data(), buf.size(), 0);
   if(rc < 0) {
      // [FIX] EAGAIN/EWOULDBLOCK은 SO_RCVTIMEO 만료를 의미함
      if(errno == EAGAIN || errno == EWOULDBLOCK) {
         throw std::runtime_error("Socket receive timed out (idle client).");
      }
      throw std::runtime_error(std::string("recv() failed: ") + std::strerror(errno));
   }
   if(rc == 0) {
      throw std::runtime_error("Peer closed TCP connection.");
   }
   channel.received_data(buf.data(), static_cast<size_t>(rc));
}

static void wait_for_tls_ready(int fd, Botan::TLS::Channel& channel,
                               const SocketTLSCallbacks& callbacks) {
   while(!channel.is_active()) {
      recv_and_feed(fd, channel);
      if(channel.is_closed()) {
         throw std::runtime_error("TLS channel closed before handshake completed.");
      }
      if(callbacks.established() && channel.is_active()) { break; }
   }
}

static std::string wait_for_line(int fd, Botan::TLS::Channel& channel,
                                 SocketTLSCallbacks& callbacks) {
   while(!callbacks.has_complete_line()) {
      recv_and_feed(fd, channel);
   }
   return callbacks.pop_line();
}

// ─────────────────────────────────────────────
// TLS Exporter + 서명
// ─────────────────────────────────────────────

static std::vector<uint8_t> exporter_binding(Botan::TLS::Channel& channel) {
   const auto key = channel.key_material_export(kBindingLabel, "", kExporterBytes);
   return std::vector<uint8_t>(key.begin(), key.end());
}

static std::vector<uint8_t> sign_bound_nonce(Botan::Private_Key& key,
                                             Botan::RandomNumberGenerator& rng,
                                             std::span<const uint8_t> nonce,
                                             std::span<const uint8_t> exporter) {
   const auto payload = make_signed_payload(nonce, exporter);
   Botan::PK_Signer signer(key, rng, "Randomized");
   return signer.sign_message(payload, rng);
}

static bool verify_bound_nonce(Botan::Public_Key& key,
                               std::span<const uint8_t> nonce,
                               std::span<const uint8_t> exporter,
                               std::span<const uint8_t> signature) {
   const auto payload = make_signed_payload(nonce, exporter);
   Botan::PK_Verifier verifier(key, "");
   return verifier.verify_message(payload, signature);
}

// ─────────────────────────────────────────────
// 프로토콜 헬퍼
// ─────────────────────────────────────────────

static std::vector<std::string> split_command(const std::string& line) {
   std::istringstream iss(line);
   std::vector<std::string> parts;
   std::string item;
   while(iss >> item) { parts.push_back(item); }
   return parts;
}

static void send_app_line(Botan::TLS::Channel& channel, const std::string& line) {
   channel.send(to_bytes(line + "\n"));
}

static std::string app_cert_pem_b64(const Botan::X509_Certificate& cert) {
   const auto pem = cert.PEM_encode();
   return encode_b64(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(pem.data()), pem.size()));
}

// ─────────────────────────────────────────────
// 서버 - 클라이언트 연결 처리 (스레드 1개)
// ─────────────────────────────────────────────

// [FIX] 연결 처리를 별도 함수로 분리 → 스레드에서 호출
static void handle_client(int fd,
                           std::shared_ptr<Botan::TLS::Session_Manager>  session_mgr,
                           std::shared_ptr<Botan::Credentials_Manager>   creds,
                           std::shared_ptr<Botan::TLS::Policy>           policy,
                           std::shared_ptr<Botan::Private_Key>           hsm_key,
                           const std::string&                             hsm_cert_sha256,
                           const std::string&                             hsm_cert_b64) {
   try {
      // [FIX] 클라이언트 소켓에 타임아웃 적용 (악성 클라이언트 hang 방지)
      set_socket_timeout(fd, kSocketTimeoutSec);

      auto callbacks = std::make_shared<SocketTLSCallbacks>(fd);
      auto rng       = std::make_shared<Botan::AutoSeeded_RNG>();

      // [FIX] 각 스레드가 독립적인 RNG와 PK_Signer를 사용 → 스레드 안전
      auto server = Botan::TLS::Server(callbacks, session_mgr, creds, policy, rng);
      wait_for_tls_ready(fd, server, *callbacks);

      for(;;) {
         const auto line  = wait_for_line(fd, server, *callbacks);
         const auto parts = split_command(line);
         if(parts.empty()) { continue; }

         if(parts[0] == "REGISTER") {
            send_app_line(server, "CERT_SHA256 " + hsm_cert_sha256);
            send_app_line(server, "CERT_B64 "    + hsm_cert_b64);
            send_app_line(server, "END");
            continue;
         }

         if(parts[0] == "AUTH" && parts.size() == 2) {
            const auto nonce    = decode_b64(parts[1]);
            const auto exporter = exporter_binding(server);
            const auto sig      = sign_bound_nonce(*hsm_key, *rng, nonce, exporter);

            send_app_line(server, "SIG_B64 " + encode_b64(sig));
            send_app_line(server, "END");
            continue;
         }

         send_app_line(server, "ERROR unsupported-command");
         send_app_line(server, "END");
      }
   } catch(const std::exception& e) {
      std::cerr << "[CLIENT] " << e.what() << "\n";
   }

   ::close(fd);
}

// ─────────────────────────────────────────────
// 서버 메인 루프
// ─────────────────────────────────────────────

static void run_server(uint16_t port,
                       const std::string& tls_cert_pem,
                       const std::string& tls_key_pem,
                       const std::string& hsm_cert_pem,
                       const std::string& hsm_private_pem) {
   // [FIX] hsm_key를 shared_ptr로 관리 → 여러 스레드에서 공유 가능
   //       PK_Signer는 sign_bound_nonce() 내에서 매번 새로 생성하므로 스레드 안전
   auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(
      std::make_shared<Botan::AutoSeeded_RNG>());
   auto creds  = std::make_shared<ServerCredentials>(tls_cert_pem, tls_key_pem);
   auto policy = std::make_shared<TLS13OnlyPolicy>();

   const auto hsm_cert       = load_certificate_from_pem_file(hsm_cert_pem);
   auto       hsm_key_raw    = load_private_key_from_pem(hsm_private_pem);
   auto       hsm_key        = std::shared_ptr<Botan::Private_Key>(std::move(hsm_key_raw));
   const auto hsm_cert_sha256 = cert_sha256_hex(hsm_cert);
   const auto hsm_cert_b64   = app_cert_pem_b64(hsm_cert);

   const int listen_fd = create_listen_socket(port);
   std::cout << "HSM server listening on TCP/" << port << "\n";
   std::cout << "HSM_CERT_SHA256: " << hsm_cert_sha256 << "\n";

   while(true) {
      sockaddr_in peer_addr{};
      socklen_t   peer_len = sizeof(peer_addr);
      const int   fd       = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&peer_addr), &peer_len);
      if(fd < 0) {
         std::cerr << "accept() failed: " << std::strerror(errno) << "\n";
         continue;
      }

      // [FIX] 연결마다 새 스레드를 생성해 독립 처리.
      //       detach()로 분리하므로 메인 루프는 즉시 다음 accept()로 복귀.
      //       각 스레드는 handle_client() 종료 시 fd를 close()함.
      std::thread(handle_client,
                  fd,
                  session_mgr,
                  creds,
                  policy,
                  hsm_key,
                  hsm_cert_sha256,
                  hsm_cert_b64).detach();
   }
}

// ─────────────────────────────────────────────
// 클라이언트 - 등록
// ─────────────────────────────────────────────

static std::pair<std::string, std::string> register_hsm(
   const std::string& ip, uint16_t port,
   const std::optional<std::string>& expected_cert_sha256) {

   const int fd = connect_tcp(ip, port);
   // [FIX] 클라이언트 소켓에도 타임아웃 적용
   set_socket_timeout(fd, kSocketTimeoutSec);

   try {
      auto callbacks   = std::make_shared<SocketTLSCallbacks>(fd);
      auto rng         = std::make_shared<Botan::AutoSeeded_RNG>();
      auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
      auto creds       = std::make_shared<ClientCredentials>();
      auto policy      = std::make_shared<TLS13OnlyPolicy>();

      Botan::TLS::Client client(callbacks, session_mgr, creds, policy, rng,
                                Botan::TLS::Server_Information(),
                                Botan::TLS::Protocol_Version::latest_tls_version());

      wait_for_tls_ready(fd, client, *callbacks);
      send_app_line(client, "REGISTER");

      std::string cert_sha256;
      std::string cert_pem;

      for(;;) {
         const auto line  = wait_for_line(fd, client, *callbacks);
         if(line == "END") { break; }

         const auto parts = split_command(line);
         if(parts.size() >= 2 && parts[0] == "CERT_SHA256") {
            cert_sha256 = parts[1];
         } else if(parts.size() >= 2 && parts[0] == "CERT_B64") {
            const auto pem_bytes = decode_b64(parts[1]);
            cert_pem.assign(reinterpret_cast<const char*>(pem_bytes.data()), pem_bytes.size());
         } else if(parts.size() >= 2 && parts[0] == "ERROR") {
            throw std::runtime_error("HSM returned error: " + parts[1]);
         }
      }

      if(cert_pem.empty() || cert_sha256.empty()) {
         throw std::runtime_error("Registration response missing certificate data.");
      }

      const auto cert         = load_certificate_from_pem_string(cert_pem);
      const auto actual_sha256 = cert_sha256_hex(cert);

      if(actual_sha256 != cert_sha256) {
         throw std::runtime_error("Certificate SHA-256 in response does not match decoded certificate.");
      }
      if(expected_cert_sha256 && actual_sha256 != *expected_cert_sha256) {
         throw std::runtime_error("Received certificate SHA-256 does not match expected pinned value.");
      }

      ::close(fd);
      return {cert_pem, actual_sha256};
   } catch(...) {
      ::close(fd);
      throw;
   }
}

// ─────────────────────────────────────────────
// 클라이언트 - 인증
// ─────────────────────────────────────────────

static void authenticate_hsm(const std::string& ip, uint16_t port,
                              const std::string& pinned_cert_pem_path) {
   const auto pinned_cert   = load_certificate_from_pem_file(pinned_cert_pem_path);
   const auto pinned_sha256 = cert_sha256_hex(pinned_cert);
   auto       pinned_pub    = pinned_cert.subject_public_key();
   if(!pinned_pub) {
      throw std::runtime_error("Failed to extract public key from pinned certificate.");
   }

   const int fd = connect_tcp(ip, port);
   // [FIX] 클라이언트 소켓에도 타임아웃 적용
   set_socket_timeout(fd, kSocketTimeoutSec);

   try {
      auto callbacks   = std::make_shared<SocketTLSCallbacks>(fd);
      auto rng         = std::make_shared<Botan::AutoSeeded_RNG>();
      auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
      auto creds       = std::make_shared<ClientCredentials>();
      auto policy      = std::make_shared<TLS13OnlyPolicy>();

      Botan::TLS::Client client(callbacks, session_mgr, creds, policy, rng,
                                Botan::TLS::Server_Information(),
                                Botan::TLS::Protocol_Version::latest_tls_version());

      wait_for_tls_ready(fd, client, *callbacks);

      std::vector<uint8_t> nonce(32);
      rng->randomize(nonce.data(), nonce.size());
      const auto exporter = exporter_binding(client);

      send_app_line(client, "AUTH " + encode_b64(nonce));

      std::vector<uint8_t> signature;
      for(;;) {
         const auto line  = wait_for_line(fd, client, *callbacks);
         if(line == "END") { break; }

         const auto parts = split_command(line);
         if(parts.size() >= 2 && parts[0] == "SIG_B64") {
            signature = decode_b64(parts[1]);
         } else if(parts.size() >= 2 && parts[0] == "ERROR") {
            throw std::runtime_error("HSM returned error: " + parts[1]);
         }
      }

      if(signature.empty()) {
         throw std::runtime_error("Authentication response missing signature.");
      }

      const bool ok = verify_bound_nonce(*pinned_pub, nonce, exporter, signature);
      std::cout << "PINNED_CERT_SHA256:" << pinned_sha256 << "\n";
      std::cout << (ok ? "AUTH_OK" : "AUTH_FAIL") << "\n";

      ::close(fd);
      if(!ok) {
         throw std::runtime_error("Pinned certificate did not verify the HSM response for this TLS session.");
      }
   } catch(...) {
      ::close(fd);
      throw;
   }
}

// ─────────────────────────────────────────────
// Usage
// ─────────────────────────────────────────────

static void print_usage(const char* argv0) {
   std::cerr
      << "Usage:\n"
      << "  " << argv0 << " sign <private_key.pem> <message_base64>\n"
      << "  " << argv0 << " verify <public_key.pem> <message_base64> <signature_base64>\n"
      << "  " << argv0 << " server <listen_port> <tls_cert.pem> <tls_key.pem> <hsm_cert.pem> <hsm_priv.pem>\n"
      << "  " << argv0 << " register <server_ip> <server_port> <hsm_cert_out.pem> [expected_cert_sha256]\n"
      << "  " << argv0 << " auth <server_ip> <server_port> <pinned_hsm_cert.pem>\n\n"
      << "Notes:\n"
      << "  - sign/verify: Pi 백엔드(tcp_server.py)가 ML-DSA 서명/검증에 사용\n"
      << "  - REGISTER: 초기 1회, HSM 인증서(공개키) 배포\n"
      << "  - AUTH: (context || nonce || TLS-exporter) 서명 → 현재 TLS 세션에 바인딩\n"
      << "  - 소켓 타임아웃: " << kSocketTimeoutSec << "초\n";
}

}  // namespace

int main(int argc, char* argv[]) {
   try {
      if(argc < 2) { print_usage(argv[0]); return 1; }

      const std::string mode = argv[1];

      // ─────────────────────────────────────────────
      // [NEW] sign 모드: tcp_server.py의 sign_with_private_key()가 호출
      //   Usage: mldsa_auth sign <private_key.pem> <message_base64>
      //   Output: SIG_BASE64:<signature_base64>
      // ─────────────────────────────────────────────
      if(mode == "sign") {
         if(argc != 4) {
            std::cerr << "Usage: " << argv[0] << " sign <private_key.pem> <message_base64>\n";
            return 1;
         }

         const auto priv_pem    = read_all_text(argv[2]);
         const auto msg_decoded = Botan::base64_decode(argv[3]);

         Botan::DataSource_Memory src(priv_pem);
         auto private_key = Botan::PKCS8::load_key(src);
         if(!private_key) {
            std::cerr << "ERROR: Failed to load private key\n";
            return 1;
         }

         Botan::AutoSeeded_RNG rng;
         Botan::PK_Signer signer(*private_key, rng, "Randomized");
         const auto sig = signer.sign_message(msg_decoded, rng);

         std::cout << "SIG_BASE64:" << Botan::base64_encode(sig) << "\n";
         return 0;
      }

      // ─────────────────────────────────────────────
      // [NEW] verify 모드: tcp_server.py의 verify_with_public_key()가 호출
      //   Usage: mldsa_auth verify <public_key.pem> <message_base64> <signature_base64>
      //   Output: OK (returncode 0) | FAIL (returncode 1)
      // ─────────────────────────────────────────────
      if(mode == "verify") {
         if(argc != 5) {
            std::cerr << "Usage: " << argv[0] << " verify <public_key.pem> <message_base64> <signature_base64>\n";
            return 1;
         }

         const auto pub_pem     = read_all_text(argv[2]);
         const auto msg_decoded = Botan::base64_decode(argv[3]);
         const auto sig_decoded = Botan::base64_decode(argv[4]);

         Botan::DataSource_Memory src(pub_pem);
         auto public_key = Botan::X509::load_key(src);
         if(!public_key) {
            std::cerr << "ERROR: Failed to load public key\n";
            return 1;
         }

         Botan::PK_Verifier verifier(*public_key, "");
         const bool ok = verifier.verify_message(msg_decoded, sig_decoded);

         std::cout << (ok ? "OK" : "FAIL") << "\n";
         return ok ? 0 : 1;
      }

      if(mode == "server") {
         if(argc != 7) { print_usage(argv[0]); return 1; }
         run_server(static_cast<uint16_t>(std::stoul(argv[2])),
                    argv[3], argv[4], argv[5], argv[6]);
         return 0;
      }

      if(mode == "register") {
         if(argc != 5 && argc != 6) { print_usage(argv[0]); return 1; }
         const std::optional<std::string> expected =
            (argc == 6) ? std::optional<std::string>(argv[5]) : std::nullopt;
         const auto [cert_pem, sha256] =
            register_hsm(argv[2], static_cast<uint16_t>(std::stoul(argv[3])), expected);
         write_text_file(argv[4], cert_pem);
         std::cout << "REGISTER_OK\n";
         std::cout << "HSM_CERT_FILE:"   << argv[4] << "\n";
         std::cout << "HSM_CERT_SHA256:" << sha256  << "\n";
         return 0;
      }

      if(mode == "auth") {
         if(argc != 5) { print_usage(argv[0]); return 1; }
         authenticate_hsm(argv[2], static_cast<uint16_t>(std::stoul(argv[3])), argv[4]);
         return 0;
      }

      print_usage(argv[0]);
      return 1;
   } catch(const std::exception& e) {
      std::cerr << "ERROR: " << e.what() << "\n";
      return 1;
   }
}
