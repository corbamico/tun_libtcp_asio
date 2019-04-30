#include <iostream>           //include cout,cerr
#include <asio.hpp>           
#include <viface/viface.hpp>  //include VIface

using namespace std::chrono; //for literal 's

namespace viface::utils
{
    //this is implemented in libviface, but not in "viface.hpp"
    //see <https://github.com/HPENetworking/libviface/blob/master/src/viface.cpp>
    //linked with libviface
    std::string hexdump(std::vector<uint8_t> const &bytes);
}   // namespace viface::utils


class tun_stream
    : public std::enable_shared_from_this<tun_stream>,
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

      public:
        std::unique_ptr<VIfaceImpl> pimpl;
        int getRX() { return pimpl->queues.rx; }
        int getTX() { return pimpl->queues.tx; }
    };

  public:
    explicit tun_stream(asio::io_context &ios)
        : io_context_(ios),
          viface_("tun0", false),
          tun_(ios, ((VIface_adaptor *)(&viface_))->getRX()),
          timer_(ios)
    {
        viface_.setIPv4("10.0.0.1");
        viface_.setIPv4Netmask("255.255.255.0");
        viface_.setMTU(1500);
    }

    void run()
    {
        //setup interface
        tun_.non_blocking(true);
        viface_.up();

        //start timer
        start_time_ = std::chrono::steady_clock::now();
        timer_.expires_after(1s);
        timer_.async_wait([this](const asio::error_code &ec) {
            this->on_timer(ec);
        });

        //start async read
        read_packet();
        io_context_.run();
    }

  private:
    void on_timer(const asio::error_code &ec)
    {
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(timer_.expiry() - start_time_);
        std::cerr << "\r[main thread] tick: " << seconds.count() << "s";
        timer_.expires_after(1s);
        timer_.async_wait([this](const asio::error_code &ec) {
            this->on_timer(ec);
        });
    }
    void read_packet()
    {
        auto buffer = streambuf_.prepare(1500);
        tun_.async_read_some(
            buffer,
            [this](const asio::error_code &ec, std::size_t bytes_read) {
                this->read_packet_done(ec, bytes_read);
            });
    }
    void read_packet_done(const asio::error_code &ec, std::size_t bytes_read)
    {
        if (!ec)
        {
            streambuf_.commit(bytes_read);
            std::vector<uint8_t> vec(streambuf_.size());
            asio::buffer_copy(asio::buffer(vec), streambuf_.data());

            std::cerr << std::endl
                      << viface::utils::hexdump(vec);
            streambuf_.consume(bytes_read);
            read_packet();
        }
    }

  private:
    asio::io_context &io_context_;
    viface::VIface viface_;

    asio::posix::stream_descriptor tun_;
    asio::steady_timer timer_;
    std::chrono::steady_clock::time_point start_time_;

    asio::streambuf streambuf_;
};

int main(int argc, char const *argv[])
{
    asio::io_context io_context;
    tun_stream server(io_context);

    std::cout << "Welcome to tun libtcp asio laboratory.\n";
    server.run();
    return 0;
}