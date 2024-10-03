#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <iomanip>
#include <iostream>

std::optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  std::vector<uint8_t> message(65536);
  sadb_msg msg{};
  // TODO: Fill sadb_msg
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type = SADB_DUMP;
  msg.sadb_msg_satype = SADB_SATYPE_ESP;
  msg.sadb_msg_len = sizeof(sadb_msg) / 8;
  msg.sadb_msg_pid = getpid();
  // TODO: Create a PF_KEY_V2 socket and write msg to it
  // Then read from socket to get SADB information
  int sockfd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  if (sockfd < 0) {
    std::cerr << "Failed to create PF_KEY_V2 socket." << std::endl;
    return std::nullopt;
  }

  ssize_t bytesWritten = write(sockfd, &msg, sizeof(sadb_msg));
  if (bytesWritten < 0) {
    std::cerr << "Failed to write to PF_KEY_V2 socket." << std::endl;
    close(sockfd);
    return std::nullopt;
  }

  ssize_t bytesRead = read(sockfd, message.data(), message.size());
  if (bytesRead < 0) {
    std::cerr << "Failed to read from PF_KEY_V2 socket." << std::endl;
    close(sockfd);
    return std::nullopt;
  }

  // TODO: Set size to number of bytes in response message
  int size = bytesRead;
  // Has SADB entry
  if (size != sizeof(sadb_msg)) {
    ESPConfig config{};
    struct sadb_ext *ext;
    bytesRead -= sizeof(sadb_msg);
    ext = (sadb_ext *)(message.data() + sizeof(sadb_msg));
    sadb_key *key;
    sadb_sa *sa;
    while(bytesRead > 0) {
      printf("ext->sadb_ext_type: %d\n", ext->sadb_ext_type);
      if (ext->sadb_ext_type == SADB_EXT_SA) {
        printf("SADB_EXT_SA\n" );
        sa = (sadb_sa *)ext;
      } else if (ext->sadb_ext_type == SADB_EXT_ADDRESS_SRC) {
        printf("SADB_EXT_ADDRESS_SRC\n" );
        sadb_address* addr = (sadb_address *)ext;
        sockaddr_in* sa = (sockaddr_in*)(addr + 1);
        uint16_t port = ntohs(sa->sin_port);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(sa->sin_addr), ip_str, INET_ADDRSTRLEN);
        printf("IP Address: %s\n", ip_str);
        config.remote = ip_str;
      } else if(ext->sadb_ext_type == SADB_EXT_ADDRESS_DST) {
        printf("SADB_EXT_ADDRESS_DST\n" );
        sadb_address* addr = (sadb_address *)ext;
        sockaddr_in* sa = (sockaddr_in*)(addr + 1);
        uint16_t port = ntohs(sa->sin_port);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(sa->sin_addr), ip_str, INET_ADDRSTRLEN);
        printf("IP Address: %s\n", ip_str);
        config.local = ip_str;
      }else if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH){
        printf("SADB_EXT_KEY_AUTH\n" );
        key = (sadb_key *)ext;
      }
      bytesRead -= ext->sadb_ext_len * 8;
      ext = (sadb_ext *)((char*)ext + ext->sadb_ext_len * 8);
      }
      config.spi = sa->sadb_sa_spi;
      std::vector<uint8_t> key_data;
      for (unsigned char *p = (unsigned char *)(key + 1), bits = key->sadb_key_bits; bits > 0; p++, bits -= 8) {
          key_data.push_back(*p);
      }
      std::span<uint8_t> key_span(key_data.data(), key_data.size());
      config.aalg = std::make_unique<ESP_AALG>(sa->sadb_sa_auth, key_span);
      if(sa->sadb_sa_encrypt != SADB_EALG_NONE) {
        config.ealg = std::make_unique<ESP_EALG>(sa->sadb_sa_encrypt, key_span);
      } else {
        config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
      }
    // TODO: Parse SADB message
    // config.spi = 0x00000000;
    // config.aalg = std::make_unique<ESP_AALG>(ALGORITHM_ID, KEY);
    // Have enc algorithm:
    //   config.ealg = std::make_unique<ESP_AALG>(ALGORITHM_ID, KEY);
    // No enc algorithm:
    //   config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
    // Source address:
    //   config.local = ipToString(ADDR);
    // Destination address:
    //   config.remote = ipToString(ADDR);
    return config;
  }
  std::cerr << "SADB entry not found." << std::endl;
  return std::nullopt;
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "------------------------------------------------------------";
  return os;
}
