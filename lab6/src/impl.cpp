#include "impl.hpp"
#include <iostream> //include cout,cerr

const uint DEFAULT_WINDOWS = 1024;
const uint MAX_SESSIONS = 1024;

namespace Tins::Utils {
Tins::RawPDU
extract_icmp_payload(Tins::ICMP& pdu)
{
  Tins::PDU::serialization_type buffer = pdu.serialize();
  size_t begin_index = pdu.header_size();
  size_t end_index = pdu.size();

  return Tins::RawPDU(buffer.begin() + begin_index, buffer.begin() + end_index);
}

/// Caculate Checksum from [begin,end)
/// and set it (uint16) to @c check_ptr
void
checksum_in_place(Tins::byte_array::const_pointer begin,
                  Tins::byte_array::const_pointer end,
                  Tins::byte_array::pointer check_ptr)
{
  auto check = ~sum_range(begin, end);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  auto uint16_ptr = reinterpret_cast<uint16_t*>(check_ptr);
  *uint16_ptr = check;
}

/// generate echo reply according to @c vec (which is ping request)
/// modify vec content, and return
/// step1. swap src_addr,dst_addr
/// step2. set type/code = 0/0
/// step2. calculate checksum ip header
/// step3. calculate checksum icmp header
void
generate_echo_reply(Tins::byte_array& vec, size_t packet_len, size_t ipheader_len)
{
  assert(packet_len > ipheader_len && ipheader_len >= 20); // NOLINT
  // step1. swap src_addr/dst_addr

  std::swap_ranges(&vec[12], &vec[16], &vec[16]); // NOLINT(cppcoreguidelines-avoid-magic-numbers)
  // step2. set type/code = Echo Reply
  vec[ipheader_len] = 0x00;
  // step3. ip header checksum
  vec[10] = vec[11] = 0x00;                                 // NOLINT(cppcoreguidelines-avoid-magic-numbers)
  checksum_in_place(&vec[0], &vec[ipheader_len], &vec[10]); // NOLINT(cppcoreguidelines-avoid-magic-numbers)
  // step4. icmp checksum
  vec[ipheader_len + 2] = vec[ipheader_len + 3] = 0x00;
  checksum_in_place(&vec[ipheader_len], &vec[packet_len], &vec[ipheader_len + 2]);
}

} // namespace Tins::Utils

bool
tcp_state_machine::context::is_ack_syn(uint32_t ack_seq /*received ack_seq*/)
{
  if (wait_ack_syn_ && (seq_syn_ < ack_seq)) {
    wait_ack_syn_ = false;
    seq_syn_ = 0;
    return true;
  }
  return false;
}

bool
tcp_state_machine::context::is_ack_fin(uint32_t ack_seq /*received ack_seq*/)
{
  if (wait_ack_fin_ && (seq_fin_ < ack_seq)) {
    wait_ack_fin_ = false;
    seq_syn_ = 0;
    return true;
  }
  return false;
}

void
tcp_state_machine::context::send_syn_ack()
{
  seq_syn_ = session_ptr_->send(Tins::TCP::SYN | Tins::TCP::ACK);
  wait_ack_syn_ = true;
}
void
tcp_state_machine::context::send_fin()
{
  seq_fin_ = session_ptr_->send(Tins::TCP::FIN | Tins::TCP::ACK);
  wait_ack_fin_ = true;
}
void
tcp_state_machine::context::send_ack()
{
  session_ptr_->send(Tins::TCP::ACK);
}
void
tcp_state_machine::context::on_close()
{
  session_ptr_->on_close();
}
void
tcp_state_machine::context::on_connect()
{
  session_ptr_->on_connect();
}
void
tcp_state_machine::context::register_timeout()
{
  session_ptr_->register_timeout();
}
void
tcp_state_machine::context::delay_close()
{
  session_ptr_->delay_close();
}
void
tcp_state_machine::context::cancel_timer()
{
  session_ptr_->cancel_timer();
}

uint32_t
tun_tcp_session::send(Tins::byte_array& payload)
{
  using namespace boost::sml::literals;
  if (payload.empty())
    return 0; // FIXME

  // only estab || closewait can send out data
  if (!sm_.is("estab"_s) && !sm_.is("closewait"_s))
    return 0; // FIXME

  uint32_t seq_sending = seq_;
  Tins::IP ip(dst_addr_, src_addr_);
  Tins::TCP tcp(dport_, sport_);
  tcp.seq(seq_);
  tcp.ack_seq(ack_seq_);
  tcp.window(DEFAULT_WINDOWS);

  ip /= tcp;
  ip /= Tins::RawPDU(payload);

  auto data = ip.serialize();
  tun_server_.send(data);

  seq_add(payload.size());
  return seq_sending;
}
uint32_t tun_tcp_session::send(Tins::small_uint<12> flags)
{
  uint32_t seq_sending = seq_;
  Tins::IP ip(dst_addr_, src_addr_);
  Tins::TCP tcp(dport_, sport_);
  tcp.seq(seq_);
  tcp.window(DEFAULT_WINDOWS);
  tcp.flags(flags);

  if (flags & Tins::TCP::ACK)
    tcp.ack_seq(ack_seq_);
  ip /= tcp;

  auto data = ip.serialize();
  tun_server_.send(data);

  if (flags & (Tins::TCP::FIN | Tins::TCP::SYN)) {
    seq_add(1U);
  }
  return seq_sending;
}

void
tun_tcp_session::close()
{
  sm_.process_event(tcp_state_machine::do_close{});
}

void
tun_tcp_session::register_timeout()
{
  timeout_.expires_after(1s);
  timeout_.async_wait([this](const asio::error_code& ec) { if(!ec) this->fire_timeout(); });
}
void
tun_tcp_session::fire_timeout()
{
  sm_.process_event(tcp_state_machine::timeout{});
}
void
tun_tcp_session::delay_close()
{
  delay_.expires_after(1s);
  delay_.async_wait([this](const asio::error_code& ec) { if(!ec) this->close(); });
}
void
tun_tcp_session::cancel_timer()
{
  //asio::error_code ec();
  delay_.cancel();  
}
void
tun_tcp_session::on_close()
{
  tun_server_.delete_session(get_key());
}

void
tun_tcp_session::on_receive(Tins::TCP& tcp)
{
  // step1. handle all seq numbers.
  ack_seq(tcp.seq());
  auto payload = tcp.inner_pdu();
  if (payload) {
    ack_seq_add(payload->size());
  } else if (tcp.flags() & (Tins::TCP::FIN | Tins::TCP::SYN)) {
    ack_seq_add(1U);
  }

  // step2. state_matchin process event
  if (tcp.get_flag(Tins::TCP::SYN))
    sm_.process_event(tcp_state_machine::rcv_syn{});

  else if (tcp.get_flag(Tins::TCP::FIN))
    sm_.process_event(tcp_state_machine::rcv_fin{});

  else if (sm_context_.is_ack_syn(tcp.ack_seq()))
    sm_.process_event(tcp_state_machine::rcv_ack_of_syn{});

  else if (sm_context_.is_ack_fin(tcp.ack_seq()))
    sm_.process_event(tcp_state_machine::rcv_ack_of_fin{});

  else if (payload && payload->size() > 0) {
    // step3. maybe no state change, receive data,
    // need ack it.
    send(Tins::TCP::ACK);
  }
}
tun_tcp_session::tun_tcp_session(tun_server& server, const Tins::IP& ip, const Tins::TCP& tcp)
  : tun_server_{ server }
  , sm_context_{ this } // can not use shared_ptr in ctor
  , sm_{ sm_context_ }
  , src_addr_(ip.dst_addr())
  , dst_addr_(ip.src_addr())
  , sport_(tcp.dport())
  , dport_(tcp.sport())
  , seq_{ 0 }
  , ack_seq_{ 0 }
  , timeout_(server.get_io_context())
  , delay_(server.get_io_context())
  , map_key_{ tun_tcp_session::get_key(ip, tcp) }
{
  // std::cerr << "\ntun_tcp_session::tun_tcp_session";
}

tun_server::tun_server(asio::io_context& ios)
  : io_context_(ios)
  , viface_("tun0", false)
  , timer_(ios)
  , channels_{
    channel(ios,
            (reinterpret_cast<VIface_adaptor*>(&viface_))->getRX()), // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    channel(ios,
            (reinterpret_cast<VIface_adaptor*>(&viface_))->getTX()) // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
  }

{
  viface_.setIPv4("10.0.0.1");
  viface_.setIPv4Netmask("255.255.255.0");
  viface_.setMTU(DEFAULT_MTU);
}

void
tun_server::run()
{
  // setup interface
  channels_[0].tun_stream_.non_blocking(true);
  channels_[1].tun_stream_.non_blocking(true);

  viface_.up();

  // start timer
  start_time_ = std::chrono::steady_clock::now();
  timer_.expires_after(1s);
  timer_.async_wait([this](const asio::error_code& ec) { this->on_timer(ec); });

  // start async read
  read_packet(channel_index::channel0);
  read_packet(channel_index::channel1);

  io_context_.run();
}
void
tun_server::send(Tins::byte_array& data)
{
  asio::async_write(channels_.at(1).tun_stream_, asio::buffer(data), [](auto ec, auto bytes_write) {});
}

void
tun_server::on_timer(const asio::error_code ec)
{
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(timer_.expiry() - start_time_);
  std::cerr << "\r[main thread] tick: " << seconds.count() << "s";
  timer_.expires_after(1s);
  timer_.async_wait([this](const asio::error_code& ec) { this->on_timer(ec); });
}
void
tun_server::read_packet(channel_index index)
{
  channel& current_channel = channels_.at(uint8_t(index));
  current_channel.tun_stream_.async_read_some(
    asio::buffer(current_channel.buffer_),
    [this, index](const asio::error_code& ec, std::size_t bytes_read) { this->read_packet_done(ec, bytes_read, index); });
}
void
tun_server::read_packet_done(const asio::error_code ec, std::size_t bytes_read, channel_index index)
{
  if ((!ec)&&(bytes_read>0)) {
    //Tins::IP ip;
    Tins::ICMP* icmp;
    Tins::TCP* tcp;

    channel& current_channel = channels_.at(uint8_t(index));
    std::copy_n(std::begin(current_channel.buffer_), bytes_read, std::begin(current_channel.writer_buffer_));

    //Bug in libtins: 
    //  ~IP().~Vector() for options_ if "_GLIBCXX_PROFILE"    
    Tins::IP ip(&current_channel.writer_buffer_[0], bytes_read);

    icmp = ip.find_pdu<Tins::ICMP>();
    tcp = ip.find_pdu<Tins::TCP>();

    // Tips: dump packet here.
    // std::cerr << std::endl << viface::utils::hexdump(vec);

    if (ip.protocol() == Tins::PROTOCOL_IP_ICMP /*1 icmp*/ && icmp != nullptr) {
      handle_icmp_packet(ip, *icmp, index);
    } else if ((ip.protocol() == Tins::PROTOCOL_IP_TCP /*6 tcp*/) && tcp != nullptr) {
      handle_tcp_packet(ip, *tcp, index);
    }
    read_packet(index);
  }
}

void
tun_server::handle_icmp_packet(Tins::IP& ip, Tins::ICMP& icmp, channel_index index)
{
  if (icmp.type() == Tins::ICMP::Flags::ECHO_REQUEST) {
    // handle icmp.echo packet from here
    // if packet is icmp.echo.request, then we reply as icmp.echo.reply
    channel& current_channel = channels_.at(uint8_t(index));
    Tins::Utils::generate_echo_reply(current_channel.writer_buffer_, ip.size(), ip.header_size());
    asio::async_write(
      current_channel.tun_stream_,
      asio::buffer(current_channel.writer_buffer_, ip.size()),
      [this, index](const asio::error_code ec, std::size_t bytes_write) { this->write_packet_done(ec, bytes_write, index); });
  }
}
void
tun_server::handle_tcp_packet(Tins::IP& ip, Tins::TCP& tcp, channel_index index)
{
  // step 1. find actvie session
  tun_tcp_session* session_ptr{ nullptr };
  auto key = tun_tcp_session::get_key(ip, tcp);

  //map.contains implements in g++-9
  if (sessions_.contains(key)) {
    // we only get raw pointer, do not move/assign unique_ptr out of map.
    // keep unique_ptr in map.
    session_ptr = sessions_.at(key).get();
  }

  // step 2. forward packet to active tun_tcp_session
  //         or else create one.
  if (tcp.get_flag(Tins::TCP::SYN)) {
    // current, only one session handle.
    if (!session_ptr) {
      //avoid syn-flood
      if (sessions_.size()>MAX_SESSIONS){
        return;
      }

      sessions_.emplace(key, tun_tcp_session::create(*this, ip, tcp));
      session_ptr = sessions_.at(key).get();
      session_ptr->on_receive(tcp);
    } else {
      // if get SYN again for active session, ignore it.
    }
  } else {
    if (session_ptr)
      session_ptr->on_receive(tcp);
  }
}
void
tun_server::write_packet_done(const asio::error_code ec, std::size_t bytes_write, channel_index queue)
{
  // currently, empty.
}

void
tun_server::delete_session(uint64_t map_key)
{
  asio::steady_timer timer(io_context_);
  timer.expires_after(3s);
  timer.async_wait([this,map_key](const asio::error_code& ec) { this->sessions_.erase(map_key); });
  //sessions_.erase(map_key);
}