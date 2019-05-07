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
    enum class QueueIndex
    {
        Queue1,
        Queue2,
    };

  public:
    explicit tun_rx_stream(asio::io_context &ios)
        : io_context_(ios),
          viface_("tun0", false),
          timer_(ios),
          buffer_1_(DEFAULT_MTU), write_buffer_1_(DEFAULT_MTU),
          buffer_2_(DEFAULT_MTU), write_buffer_2_(DEFAULT_MTU),
          //NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          tun_rx_(ios, (reinterpret_cast<VIface_adaptor *>(&viface_))->getRX()),
          //NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          tun_tx_(ios, (reinterpret_cast<VIface_adaptor *>(&viface_))->getTX())
    {
        viface_.setIPv4("10.0.0.1");
        viface_.setIPv4Netmask("255.255.255.0");
        viface_.setMTU(DEFAULT_MTU);
    }

    void run()
    {
        //setup interface
        tun_rx_.non_blocking(true);
        viface_.up();

        //start timer
        start_time_ = std::chrono::steady_clock::now();
        timer_.expires_after(1s);
        timer_.async_wait([this](const asio::error_code &ec) {
            this->on_timer(ec);
        });

        //start async read
        read_packet(QueueIndex::Queue1);
        read_packet(QueueIndex::Queue2);

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
    void read_packet(QueueIndex queue)
    {
        if (queue == QueueIndex::Queue1)
        {
            tun_rx_.async_read_some(
                asio::buffer(buffer_1_),
                [this, queue](const asio::error_code &ec, std::size_t bytes_read) {
                    this->read_packet_done(ec, bytes_read, queue);
                });
        }
        else
        {
            tun_tx_.async_read_some(
                asio::buffer(buffer_2_),
                [this, queue](const asio::error_code &ec, std::size_t bytes_read) {
                    this->read_packet_done(ec, bytes_read, queue);
                });
        }
    }
    void read_packet_done(const asio::error_code ec, std::size_t bytes_read, QueueIndex queue)
    {
        if (!ec)
        {
            Tins::IP ip;
            Tins::ICMP *icmp;

            if (queue == QueueIndex::Queue1)
            {
                std::copy_n(std::begin(buffer_1_), bytes_read, std::begin(write_buffer_1_));
                ip = Tins::IP(&write_buffer_1_[0], bytes_read);
                icmp = ip.find_pdu<Tins::ICMP>();
            }
            else
            {
                std::copy_n(std::begin(buffer_2_), bytes_read, std::begin(write_buffer_2_));
                ip = Tins::IP(&write_buffer_1_[0], bytes_read);
                icmp = ip.find_pdu<Tins::ICMP>();
            }

            // Tips: dump packet here.
            // std::cerr << std::endl
            //           << viface::utils::hexdump(vec);

            if (ip.protocol() == 1 /*icmp*/
                && icmp != nullptr && icmp->type() == Tins::ICMP::Flags::ECHO_REQUEST)
            {
                //if packet is icmp.echo.request, then we reply as icmp.echo.reply
                if (queue == QueueIndex::Queue1)
                {
                    //since we use different buffer for read/write,
                    //we can call read_packet immediate.
                    Tins::Utils::generate_echo_reply(write_buffer_1_, bytes_read, ip.header_size());
                    asio::async_write(tun_rx_,
                                      asio::buffer(write_buffer_1_, bytes_read),
                                      [this, queue](const asio::error_code ec, std::size_t bytes_write) {
                                          this->write_packet_done(ec, bytes_write, queue);
                                      });
                    
                }
                else
                {
                    Tins::Utils::generate_echo_reply(write_buffer_2_, bytes_read, ip.header_size());
                    asio::async_write(tun_tx_,
                                      asio::buffer(write_buffer_2_, bytes_read),
                                      [this, queue](const asio::error_code ec, std::size_t bytes_write) {
                                          this->write_packet_done(ec, bytes_write, queue);
                                      });
                    
                }
            }
            read_packet(queue);
        }
    }

    inline void write_packet_done(const asio::error_code ec, std::size_t bytes_write, QueueIndex queue)
    {
    }

  private:
    asio::io_context &io_context_;
    viface::VIface viface_;

    asio::posix::stream_descriptor tun_rx_; //libivface use 2 queue
    asio::posix::stream_descriptor tun_tx_; //libivface use 2 queue

    asio::steady_timer timer_;
    std::chrono::steady_clock::time_point start_time_;

    std::vector<uint8_t> buffer_1_; //read buffer for queue 1
    std::vector<uint8_t> buffer_2_; //read buffer for queue 2

    std::vector<uint8_t> write_buffer_1_; //write buffer for queue 1
    std::vector<uint8_t> write_buffer_2_; //write buffer for queue 2
};

int main(int argc, char const *argv[])
{
    asio::io_context io_context;
    tun_rx_stream server(io_context);

    std::cout << "Welcome to tun libtcp asio laboratory.\n";
    server.run();
    return 0;
}