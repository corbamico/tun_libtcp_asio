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

namespace Tins::utils
{
    Tins::RawPDU extract_icmp_payload(Tins::ICMP &pdu)
    {
        Tins::PDU::serialization_type buffer = pdu.serialize();
        size_t begin_index = pdu.header_size();
        size_t end_index = pdu.size();

        return Tins::RawPDU(buffer.begin() + begin_index, buffer.begin() + end_index);
    }

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
}


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
          stream_queue_1_(),
          stream_queue_2_(),
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
        asio::mutable_buffer buffer;
        if (queue == QueueIndex::Queue1)
        {
            stream_queue_1_.consume(stream_queue_1_.size());
            buffer = stream_queue_1_.prepare(DEFAULT_MTU);
            tun_rx_.async_read_some(
                buffer,
                [this, queue](const asio::error_code &ec, std::size_t bytes_read) {
                    this->read_packet_done(ec, bytes_read, queue);
                });
        }
        else
        {
            stream_queue_2_.consume(stream_queue_2_.size());
            buffer = stream_queue_2_.prepare(DEFAULT_MTU);
            tun_tx_.async_read_some(
                buffer,
                [this, queue](const asio::error_code &ec, std::size_t bytes_read) {
                    this->read_packet_done(ec, bytes_read, queue);
                });
        }
    }
    void read_packet_done(const asio::error_code ec, std::size_t bytes_read, QueueIndex queue)
    {
        asio::streambuf *pbuffer = nullptr;
        if (!ec)
        {
            pbuffer = (queue == QueueIndex::Queue1) ? (&stream_queue_1_) : (&stream_queue_2_);
            // The actual number of bytes received is committed to the buffer so that we
            // can extract it using a std::istream object.

            pbuffer->commit(bytes_read);

            std::vector<uint8_t> vec(pbuffer->size());
            
            asio::buffer_copy(asio::buffer(vec), pbuffer->data());

            // Tips: dump packet here.
            std::cerr << std::endl
                      << viface::utils::hexdump(vec);


            auto ip = Tins::IP(&vec[0], vec.size());
            auto icmp = ip.find_pdu<Tins::ICMP>();

            if (ip.protocol() == 1 /*icmp*/
                && icmp != nullptr && icmp->type() == Tins::ICMP::Flags::ECHO_REQUEST)
            {
                //if packet is icmp.echo.request, then we reply as icmp.echo.reply
                auto reply = Tins::utils::generate_echo_reply(ip, *icmp);
                if (queue == QueueIndex::Queue1)
                {
                    asio::async_write(tun_rx_,
                                      asio::buffer(reply),
                                      [this, queue](const asio::error_code ec, std::size_t bytes_write) {
                                          this->write_packet_done(ec, bytes_write, queue);
                                      });
                }
                else
                {
                    asio::async_write(tun_tx_,
                                      asio::buffer(reply),
                                      [this, queue](const asio::error_code ec, std::size_t bytes_write) {
                                          this->write_packet_done(ec, bytes_write, queue);
                                      });
                }
            }
        }
    }

    void write_packet_done(const asio::error_code ec, std::size_t bytes_write, QueueIndex queue)
    {
        read_packet(queue);
    }

  private:
    asio::io_context &io_context_;
    viface::VIface viface_;

    asio::posix::stream_descriptor tun_rx_; //libivface use 2 queue
    asio::posix::stream_descriptor tun_tx_; //libivface use 2 queue

    asio::steady_timer timer_;
    std::chrono::steady_clock::time_point start_time_;

    asio::streambuf stream_queue_1_; //read buffer for ip/tcp, icmp; libivface use 2 queue
    asio::streambuf stream_queue_2_; //read buffer for icmp
    asio::streambuf stream_writer_;
};

int main(int argc, char const *argv[])
{
    asio::io_context io_context;
    tun_rx_stream server(io_context);

    std::cout << "Welcome to tun libtcp asio laboratory.\n";
    server.run();
    return 0;
}