#ifndef __IMPL_HPP__
#define __IMPL_HPP__

#include <asio.hpp>
#include <boost/sml.hpp>
#include <functional>
#include <iostream>
#include <tins/tins.h>
#include <viface/viface.hpp> //include VIface

using namespace std::chrono; // for literal 's

const uint DEFAULT_MTU = 1500;

namespace viface::utils {
// this is implemented in libviface, but not in "viface.hpp"
// see <https://github.com/HPENetworking/libviface/blob/master/src/viface.cpp>
// linked with libviface
std::string
hexdump(std::vector<uint8_t> const& bytes);
} // namespace viface::utils

namespace Tins {
namespace Utils {
Tins::RawPDU
extract_icmp_payload(Tins::ICMP& pdu);

/// Caculate Checksum from [begin,end)
/// and set it (uint16) to @c check_ptr
void
checksum_in_place(Tins::byte_array::const_pointer begin,
                  Tins::byte_array::const_pointer end,
                  Tins::byte_array::pointer check_ptr);

/// generate echo reply according to @c vec (which is ping request)
/// modify vec content, and return
void
generate_echo_reply(Tins::byte_array& vec, size_t packet_len, size_t ipheader_len);
} // namespace Utils

/// PDU_Proxy
/// Since IP::serialize(uint8_t*,uint32_t) is protected,
/// we need expose it to public
/// Example:
///< code>
/// using Tins::IP;
/// using Tins::PDU_Proxy;
/// IP ip(...);
/// PDU_Proxy<IP>* ip_ptr = (static_cast<PDU_Proxy<IP> *> (&ip);
/// ip_ptr->serialize(...);
///</code>
template<class T>
class PDU_Proxy : public T
{
public:
  void serialize(uint8_t* buffer, uint32_t total_sz) { T::serialize(buffer, total_sz); }
};
using IP_Proxy = PDU_Proxy<IP>;
enum __unnamed_enum_protocol__
{
  PROTOCOL_IP_ICMP = 1,
  PROTOCOL_IP_TCP = 6,
};
} // namespace Tins

class tun_tcp_session;
/// struct tcp_state_machine
struct tcp_state_machine
{
  struct context
  {
    tun_tcp_session* session_ptr_;

    bool wait_ack_syn_{ false };
    bool wait_ack_fin_{ false };
    uint32_t seq_syn_{ 0 }; // help check event rcv_ack_of_syn
    uint32_t seq_fin_{ 0 }; // help check event rcv_ack_of_fin

    bool is_ack_syn(uint32_t ack_seq /*received ack_seq*/);
    bool is_ack_fin(uint32_t ack_seq /*received ack_seq*/);

    void send_syn_ack();
    void send_ack();
    void send_fin();
    void delete_tcb();

    void on_connect();
    void on_close();
    void register_timeout();
    void delay_close();
    void cancel_timer();
  };
  /// events
  struct rcv_syn
  {};
  struct rcv_ack_of_syn
  {};
  struct do_close
  {};
  struct rcv_fin
  {};
  struct rcv_ack_of_fin
  {};
  struct timeout
  {};

  auto operator()() const
  {
    ///                               +---------+ ---------\      active OPEN
    ///                               |  CLOSED |            \    -----------
    ///                               +---------+<---------\   \   create TCB
    ///                                 |     ^              \   \  snd SYN
    ///                    passive OPEN |     |   CLOSE        \   \
    ///                    ------------ |     | ----------       \   \
    ///                     create TCB  |     | delete TCB         \   \
    ///                                 V     |                      \   \
    ///                               +---------+            CLOSE    |    \
    ///                               |  LISTEN |          ---------- |     |
    ///                               +---------+          delete TCB |     |
    ///                    rcv SYN      |     |     SEND              |     |
    ///                   -----------   |     |    -------            |     V
    ///  +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
    ///  |         |<-----------------           ------------------>|         |
    ///  |   SYN   |                    rcv SYN                     |   SYN   |
    ///  |   RCVD  |<-----------------------------------------------|   SENT  |
    ///  |         |                    snd ACK                     |         |
    ///  |         |------------------           -------------------|         |
    ///  +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
    ///    |           --------------   |     |   -----------
    ///    |                  x         |     |     snd ACK
    ///    |                            V     V
    ///    |  CLOSE                   +---------+
    ///    | -------                  |  ESTAB  |
    ///    | snd FIN                  +---------+
    ///    |                   CLOSE    |     |    rcv FIN
    ///    V                  -------   |     |    -------
    ///  +---------+          snd FIN  /       \   snd ACK          +---------+
    ///  |  FIN    |<-----------------           ------------------>|  CLOSE  |
    ///  | WAIT-1  |------------------                              |   WAIT  |
    ///  +---------+          rcv FIN  \                            +---------+
    ///    | rcv ACK of FIN   -------   |                            CLOSE  |
    ///    | --------------   snd ACK   |                           ------- |
    ///    V        x                   V                           snd FIN V
    ///  +---------+                  +---------+                   +---------+
    ///  |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
    ///  +---------+                  +---------+                   +---------+
    ///    |                rcv ACK of FIN |                 rcv ACK of FIN |
    ///    |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
    ///    |  -------              x       V    ------------        x       V
    ///     \ snd ACK                 +---------+delete TCB         +---------+
    ///      ------------------------>|TIME WAIT|------------------>| CLOSED  |
    ///                               +---------+                   +---------+
    ///
    ///                       TCP Connection State Diagram
    using namespace boost::sml;
    // auto act_send_syn = [] (context& ctx) {ctx.send_syn();};
    auto act_send_fin = [](context& ctx) { ctx.send_fin(); };
    auto act_send_ack = [](context& ctx) { ctx.send_ack(); };
    auto act_send_syn_ack = [](context& ctx) { ctx.send_syn_ack(); };
    auto act_delete_tcb = [] {};

    auto act_entry_esatb = [](context& ctx) { ctx.on_connect(); };
    auto act_entry_timewait = [](context& ctx) { ctx.register_timeout(); };
    auto act_entry_closed = [](context& ctx) { ctx.on_close(); };

    // this is in server side, force us do_close in closewait,
    // even though this is not in standard 'TCP Connection State Diagram'
    auto act_entry_closewait = [](context& ctx) { ctx.delay_close(); };
    auto act_entry_synrcvd   = [](context& ctx) { ctx.delay_close(); };
    auto act_exit_synrcvd   = [](context& ctx) { ctx.cancel_timer(); };

    // clang-format off
    return make_transition_table(
       *"listen"_s    + event<rcv_syn> / act_send_syn_ack  = "synrcvd"_s,
        "synrcvd"_s   + event<rcv_ack_of_syn>              = "estab"_s,
        "estab"_s     + event<rcv_fin> / act_send_ack      = "closewait"_s,
        "estab"_s     + event<do_close> / act_send_fin     = "finwait1"_s,
        "closewait"_s + event<do_close> / act_send_fin     = "lastack"_s,
        "lastack"_s   + event<rcv_ack_of_fin>              = "closed"_s,
        "finwait1"_s  + event<rcv_ack_of_fin>              = "finwait2"_s,
        "finwait2"_s  + event<rcv_fin> / act_send_ack      = "timewait"_s,
        "finwait1"_s  + event<rcv_fin> / act_send_ack      = "closing"_s,
        "closing"_s   + event<rcv_ack_of_fin>              = "timewait"_s,
        "timewait"_s  + event<timeout> / act_delete_tcb    = "closed"_s,
        "closed"_s                                         = X,
        
        "estab"_s     + on_entry<_> / act_entry_esatb,
        "timewait"_s  + on_entry<_> / act_entry_timewait,
        "closed"_s    + on_entry<_> / act_entry_closed,        
        "closewait"_s + on_entry<_> / act_entry_closewait,
        "synrcvd"_s   + on_entry<_> / act_entry_synrcvd,
        "synrcvd"_s   + boost::sml::on_exit<_>  / act_exit_synrcvd
        );
    // clang-format on
  }
};

class tun_server;
class tun_tcp_session
  : public std::enable_shared_from_this<tun_tcp_session>
  , private asio::detail::noncopyable
{
private:
  void ack_seq(uint32_t seq)
  {
    if (seq > ack_seq_)
      ack_seq_ = seq;
  }
  void seq_add(size_t num) { seq_ += num; }
  void ack_seq_add(size_t num) { ack_seq_ += num; }
  explicit tun_tcp_session(tun_server&, const Tins::IP&, const Tins::TCP&);

  // make make_shared can access private ctor.
  // see ref https://stackoverflow.com/questions/8147027
  // gcc output as [with _Up = tun_tcp_session; _Args = {tun_server&}; _Tp = tun_tcp_session]'
  // NOLINTNEXTLINT
  // template<typename _Up, typename... _Args> friend void __gnu_cxx::new_allocator<tun_tcp_session>::construct(_Up*,
  // _Args&&...);
  // NOLINTNEXTLINT
  template<typename _Tp, typename... _Args>
  friend typename std::_MakeUniq<_Tp>::__single_object std::make_unique(_Args&&...);

  void on_receive(Tins::TCP& tcp);
  friend class tun_server;

public:
  uint32_t send(Tins::byte_array& payload);
  uint32_t send(Tins::small_uint<12> flags);
  void close();
  void register_timeout();
  void fire_timeout();
  void delay_close();
  void cancel_timer();

  /// on_close()
  /// sm entry 'closed state'
  /// notify server to delete session self.
  virtual void on_close();
  virtual void on_data(){};
  virtual void on_connect(){};

  static std::unique_ptr<tun_tcp_session> create(tun_server& server, const Tins::IP& ip, const Tins::TCP& tcp)
  {
    return std::make_unique<tun_tcp_session>(server, ip, tcp);
  }

  uint64_t get_key() const{return map_key_;}
  static uint64_t get_key(const Tins::IP& ip, const Tins::TCP& tcp)
  {
    return uint64_t(tcp.sport()) << 32 | uint64_t(uint32_t(ip.src_addr()));
  }
  ~tun_tcp_session() = default;
  // {
  //   // std::cerr<<"\n[debug] ~tun_tcp_session() called. \n";
  // }

private:
  tcp_state_machine::context sm_context_;
  boost::sml::sm<tcp_state_machine> sm_;

  Tins::IPv4Address src_addr_, dst_addr_;
  uint16_t sport_, dport_;
  uint32_t seq_, ack_seq_;
  tun_server& tun_server_;
  const uint64_t map_key_;

  asio::steady_timer timeout_; // used for tcp_state_matchine.TIMEOUT
  asio::steady_timer delay_;
};

class tun_server
  : public std::enable_shared_from_this<tun_server>
  , private asio::detail::noncopyable
{
#pragma region "tun_server inner struct"
  // since libviface does NOT export getRX(), we need fake it.
  // orignal source see
  // <https://github.com/HPENetworking/libviface/blob/master/include/viface/private/viface.hpp>
  class VIface_adaptor
  {
    struct viface_queues
    {
      int rx;
      int tx;
    };
    struct VIfaceImpl
    {
      struct viface_queues queues;
    };
    std::unique_ptr<VIfaceImpl> pimpl;

  public:
    int getRX() { return pimpl->queues.rx; }
    int getTX() { return pimpl->queues.tx; }
  };
  enum class channel_index
  {
    channel0 = 0,
    channel1 = 1,
  };
  struct channel
  {
    channel(asio::io_context& ios, int rawfd)
      : tun_stream_(ios, rawfd)
      , buffer_(DEFAULT_MTU)
      , writer_buffer_(DEFAULT_MTU)
    {}
    asio::posix::stream_descriptor tun_stream_; // libivface use 2 RawFD, usually 1 for rx,2 for tx
                                                // but sometimes, icmp packet comes from tx.
    std::vector<uint8_t> buffer_;               // read buffer
    std::vector<uint8_t> writer_buffer_;        // writer buffer
  };
#pragma endregion "tun_server inner struct"

public:
  explicit tun_server(asio::io_context& ios);

  void run();

  /// FIXME: need async function call.
  void send(Tins::byte_array& data);

  asio::io_context& get_io_context() const { return io_context_; } 

  //delete_session should be delay exec, can not call from session itself. 
  void delete_session(uint64_t map_key);

private:
  void on_timer(const asio::error_code ec);
  void read_packet(channel_index index);
  void read_packet_done(const asio::error_code ec, std::size_t bytes_read, channel_index index);
  void handle_icmp_packet(Tins::IP& ip, Tins::ICMP& icmp, channel_index index);
  void handle_tcp_packet(Tins::IP& ip, Tins::TCP& tcp, channel_index index);
  void write_packet_done(const asio::error_code ec, std::size_t bytes_write, channel_index queue);

private:
  asio::io_context& io_context_;
  viface::VIface viface_;
  asio::steady_timer timer_;
  std::chrono::steady_clock::time_point start_time_;
  std::array<channel, 2> channels_;

  /// keep all active session in sessions_
  /// key caculated as (source_port << 32 | source_ip)
  std::map<uint64_t, std::unique_ptr<tun_tcp_session> > sessions_;
};

#endif