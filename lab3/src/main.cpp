#include <asio.hpp>
#include <iostream> //include cout,cerr
#include <tins/tins.h>
#include <viface/viface.hpp> //include VIface

using namespace std::chrono; //for literal 's

const uint DEFAULT_MTU = 1500;

namespace viface::utils
{
//this is implemented in libviface, but not in "viface.hpp"
//see <https://github.com/HPENetworking/libviface/blob/master/src/viface.cpp>
//linked with libviface
std::string hexdump(std::vector<uint8_t> const &bytes);
} // namespace viface::utils

namespace Tins::Utils
{
Tins::RawPDU extract_icmp_payload(Tins::ICMP &pdu)
{
    Tins::PDU::serialization_type buffer = pdu.serialize();
    size_t begin_index = pdu.header_size();
    size_t end_index = pdu.size();

    return Tins::RawPDU(buffer.begin() + begin_index, buffer.begin() + end_index);
}

///generate echo reply according to @c ip @c icmp
///return byte vector
Tins::byte_array generate_echo_reply(Tins::IP &ip, Tins::ICMP &icmp)
{
    Tins::IP response_ip(ip.src_addr(), ip.dst_addr());
    Tins::ICMP response_icmp{};
    response_icmp.set_echo_reply(icmp.id(), icmp.sequence());
    response_ip.ttl(ip.ttl());
    response_ip /= response_icmp;
    response_ip /= extract_icmp_payload(icmp);

    return response_ip.serialize();
}
///Caculate Checksum from [begin,end)
///and set it (uint16) to @c check_ptr
void checksum_in_place(Tins::byte_array::const_pointer begin,
                       Tins::byte_array::const_pointer end,
                       Tins::byte_array::pointer check_ptr)
{
    auto check = ~sum_range(begin, end);
    //NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto uint16_ptr = reinterpret_cast<uint16_t *>(check_ptr);
    *uint16_ptr = check;
}

///generate echo reply according to @c vec (which is ping request)
///modify vec content, and return
/// step1. swap src_addr,dst_addr
/// step2. set type/code = 0/0
/// step2. calculate checksum ip header
/// step3. calculate checksum icmp header
void generate_echo_reply(Tins::byte_array &vec,
                         size_t packet_len,
                         size_t ipheader_len)
{
    assert(packet_len > ipheader_len && ipheader_len >= 20); //NOLINT
    //step1. swap src_addr/dst_addr

    std::swap_ranges(&vec[12], &vec[16], &vec[16]); //NOLINT(cppcoreguidelines-avoid-magic-numbers)
    //step2. set type/code = Echo Reply
    vec[ipheader_len] = 0x00;
    //step3. ip header checksum
    vec[10] = vec[11] = 0x00;                                 //NOLINT(cppcoreguidelines-avoid-magic-numbers)
    checksum_in_place(&vec[0], &vec[ipheader_len], &vec[10]); //NOLINT(cppcoreguidelines-avoid-magic-numbers)
    //step4. icmp checksum
    vec[ipheader_len + 2] = vec[ipheader_len + 3] = 0x00;
    checksum_in_place(&vec[ipheader_len], &vec[packet_len], &vec[ipheader_len + 2]);
}

} // namespace Tins::Utils

class tun_rx_stream
    : public std::enable_shared_from_this<tun_rx_stream>,
      private asio::detail::noncopyable
{

    //since libviface does NOT export getRX(), we need fake it.
    //orignal source see <https://github.com/HPENetworking/libviface/blob/master/include/viface/private/viface.hpp>
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
        channel(asio::io_context &ios, int rawfd)
            : tun_stream_(ios, rawfd),
              buffer_(DEFAULT_MTU),
              writer_buffer_(DEFAULT_MTU) {}
        asio::posix::stream_descriptor tun_stream_; //libivface use 2 RawFD, usually 1 for rx,2 for tx
                                                    //but sometimes, icmp packet comes from tx.
        std::vector<uint8_t> buffer_;               //read buffer
        std::vector<uint8_t> writer_buffer_;        //writer buffer
    };

  public:
    explicit tun_rx_stream(asio::io_context &ios)
        : io_context_(ios),
          viface_("tun0", false),
          timer_(ios),
          channels_{
              channel(ios, (reinterpret_cast<VIface_adaptor *>(&viface_))->getRX()), //NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
              channel(ios, (reinterpret_cast<VIface_adaptor *>(&viface_))->getTX())  //NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
              }
    {
        viface_.setIPv4("10.0.0.1");
        viface_.setIPv4Netmask("255.255.255.0");
        viface_.setMTU(DEFAULT_MTU);
    }

    void run()
    {
        //setup interface
        channels_[0].tun_stream_.non_blocking(true);
        channels_[1].tun_stream_.non_blocking(true);

        viface_.up();

        //start timer
        start_time_ = std::chrono::steady_clock::now();
        timer_.expires_after(1s);
        timer_.async_wait([this](const asio::error_code &ec) {
            this->on_timer(ec);
        });

        //start async read
        read_packet(channel_index::channel0);
        read_packet(channel_index::channel1);

        io_context_.run();
    }

  private:
    void on_timer(const asio::error_code ec)
    {
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(timer_.expiry() - start_time_);
        std::cerr << "\r[main thread] tick: " << seconds.count() << "s";
        timer_.expires_after(1s);
        timer_.async_wait([this](const asio::error_code &ec) {
            this->on_timer(ec);
        });
    }
    void read_packet(channel_index index)
    {
        channel &current_channel = channels_.at(uint8_t(index));
        current_channel
            .tun_stream_
            .async_read_some(
                asio::buffer(current_channel.buffer_),
                [this, index](const asio::error_code &ec, std::size_t bytes_read) {
                    this->read_packet_done(ec, bytes_read, index);
                });
    }
    void read_packet_done(
        const asio::error_code ec,
        std::size_t bytes_read,
        channel_index index)
    {
        if (!ec)
        {
            Tins::IP ip;
            Tins::ICMP *icmp;

            channel &current_channel = channels_.at(uint8_t(index));
            std::copy_n(std::begin(current_channel.buffer_), bytes_read, std::begin(current_channel.writer_buffer_));
            ip = Tins::IP(&current_channel.writer_buffer_[0], bytes_read);
            icmp = ip.find_pdu<Tins::ICMP>();

            // Tips: dump packet here.
            // std::cerr << std::endl
            //           << viface::utils::hexdump(vec);

            if (ip.protocol() == 1 /*icmp*/
                && icmp != nullptr && icmp->type() == Tins::ICMP::Flags::ECHO_REQUEST)
            {
                //if packet is icmp.echo.request, then we reply as icmp.echo.reply
                Tins::Utils::generate_echo_reply(current_channel.writer_buffer_, bytes_read, ip.header_size());
                asio::async_write(current_channel.tun_stream_,
                                  asio::buffer(current_channel.writer_buffer_, bytes_read),
                                  [this, index](const asio::error_code ec, std::size_t bytes_write) {
                                      this->write_packet_done(ec, bytes_write, index);
                                  });
            }
            read_packet(index);
        }
    }

    inline void write_packet_done(const asio::error_code ec, std::size_t bytes_write, channel_index queue)
    {
    }

  private:
    asio::io_context &io_context_;
    viface::VIface viface_;
    asio::steady_timer timer_;
    std::chrono::steady_clock::time_point start_time_;
    std::array<channel,2> channels_; 
};

int main(int argc, char const *argv[])
{
    asio::io_context io_context;
    tun_rx_stream server(io_context);

    std::cout << "Welcome to tun libtcp asio laboratory.\n";
    server.run();
    return 0;
}