#include "session.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iomanip>

#include <iostream>
#include <span>
#include <utility>

extern bool running;

void printBytes(const uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]) << " ";
    }
    std::cout << std::endl;
}

Session::Session(const std::string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  addr_ll.sll_family = AF_PACKET;
  addr_ll.sll_protocol = htons(ETH_P_ALL);  
  addr_ll.sll_ifindex = if_nametoindex(iface.c_str());
  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}

void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  std::string secret;
  std::cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        std::getline(std::cin, secret);
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) encapsulate("");
        if (!secret.empty() && state.recvPacket) {
          //std::cout << "Secret: " << secret << std::endl;
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  dissectIPv4(payload);
}

uint32_t saddr;
uint32_t daddr;
int tot_len;
void Session::dissectIPv4(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO:
  // Set `recvPacket = true` if we are receiving packet from remote
  saddr = hdr.saddr;
  daddr = hdr.daddr;
  tot_len = hdr.tot_len;

  if(ipToString(saddr) == config.remote.c_str()){
    state.recvPacket = true;
  }else{
    state.recvPacket = false;
  }
  // Track current IP id
  state.ipId = hdr.id;

  // Call dissectESP(payload) if next protocol is ESP
  if (hdr.protocol == IPPROTO_ESP) {
      auto payload = buffer.subspan(hdr.ihl * 4);
      dissectESP(payload);
  } 
}

uint32_t spi ;
void Session::dissectESP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  
  int hashLength = config.aalg->hashLength();
  // Strip hash
  buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength);
  std::vector<uint8_t> data;
  // Decrypt payload
  if (!config.ealg->empty()) {
    data = config.ealg->decrypt(buffer);
    buffer = std::span{data.data(), data.size()};
  }
  // TODO:
  // Track ESP sequence number
  if(state.recvPacket == false) {
    spi = hdr.spi;
    state.espseq = hdr.seq + htonl(1);
  }
  
  // Call dissectTCP(payload) if next protocol is TCP
  std::array<uint8_t, sizeof(ESPTrailer)> trailerData;
  std::memcpy(trailerData.data(), buffer.last(sizeof(ESPTrailer)).data(), sizeof(ESPTrailer));
  ESPTrailer tlr;
  std::memcpy(&tlr, trailerData.data(), sizeof(ESPTrailer));
  if (static_cast<int>(tlr.next) == IPPROTO_TCP) {
      auto payload = std::span{buffer.data(), buffer.size() - sizeof(ESPTrailer) - tlr.padlen};
      dissectTCP(payload);
  }
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);
  // Track tcp parameters
  state.tcpseq =  hdr.seq  + htonl(payload.size());
  state.tcpackseq = hdr.ack_seq;
  state.srcPort = hdr.source;
  state.dstPort =  hdr.dest;

  // Is ACK message?
  if (payload.empty()) {
    //std::cout << "ACK\n";
    return;
  }
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
  }
}

void Session::encapsulate(const std::string& payload) {
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

uint16_t calculateChecksum(const uint16_t* data, size_t len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *reinterpret_cast<const uint8_t*>(data);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(sum);
}

int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO: Fill IP header
  hdr.version = 4;
  hdr.ihl = 5;
  hdr.ttl = 64;
  hdr.id = state.ipId;
  hdr.protocol = IPPROTO_ESP;
  hdr.frag_off = 0;
  hdr.saddr = daddr;
  hdr.daddr = saddr;
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));
  int payloadLength = encapsulateESP(nextBuffer, payload);

  payloadLength += sizeof(iphdr);
  hdr.tot_len = htons(payloadLength);
  hdr.check = 0;
  hdr.check = calculateChecksum(reinterpret_cast<uint16_t*>(&hdr), sizeof(iphdr));
  hdr.check = ~hdr.check;
  return payloadLength;
}


int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  // TODO: Fill ESP header
  //std::cout << "encapsulate ESP\n";
  hdr.spi = spi;
  hdr.seq = state.espseq;
  //std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << hdr.seq << std::endl;
  
  //std::cout<<"encapedESP seq: "<< std::endl;
  //std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << hdr.seq << std::endl;
  int payloadLength = encapsulateTCP(nextBuffer, payload);
  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);
  // TODO: Calculate padding size and do padding in `endBuffer`
  int padSize = 16 - (payloadLength % 16);
  if(padSize == 16) padSize = 0;
  payloadLength += padSize;
  for(int i = 1; i <= padSize; i++){
    endBuffer[i - 1] = i ;
  }
  // ESP trailer
  endBuffer[padSize] = padSize;
  endBuffer[padSize + 1] = 0x06; 
  payloadLength += sizeof(ESPTrailer);
  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }
  payloadLength += sizeof(ESPHeader);

  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    auto result = config.aalg->hash(buffer.first(payloadLength));
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }
  return payloadLength;
}

uint16_t calculateTCPChecksum(const uint16_t* data, size_t len, const uint16_t* data2, size_t len2) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *reinterpret_cast<const uint8_t*>(data);
    }
    while (len2 > 1) {
        sum += *data2++;
        len2 -= 2;
    }
    if (len2 == 1) {
        sum += *reinterpret_cast<const uint8_t*>(data2);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()) hdr.psh = 1;
  // TODO: Fill TCP header
  hdr.ack = 1;
  hdr.doff = 5;
  hdr.dest = state.srcPort;
  hdr.source = state.dstPort;
  hdr.ack_seq = state.tcpseq;
  hdr.seq = state.tcpackseq;
  hdr.window = htons(502);
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }

  // TODO: Update TCP sequence number
  state.tcpseq = hdr.seq + payloadLength;
  payloadLength += sizeof(tcphdr);
  // TODO: Compute checksum 
  PseudoIPv4Header pseudoHdr;
  pseudoHdr.src = daddr;
  pseudoHdr.dst = saddr;
  pseudoHdr.zero = 0;
  pseudoHdr.protocol = 0x06;
  uint16_t check = 0;
  hdr.check = 0;
  pseudoHdr.length = htons(payloadLength);
  hdr.check = calculateTCPChecksum(reinterpret_cast<uint16_t*>(&hdr), sizeof(tcphdr) + payloadLength, reinterpret_cast<uint16_t*>(&pseudoHdr), sizeof(PseudoIPv4Header));
  std::cout << std::endl;
  return payloadLength;
}

