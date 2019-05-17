#include <iostream>  //include cout,cerr
#include "impl.hpp"

int main(int argc, char const *argv[]) {
  asio::io_context io_context;
  tun_server server(io_context);

  // boost::sml::sm<tcp_state_machine> sm{};
  // sm.process_event(tcp_state_machine::rcv_syn{});

  // sm.visit_current_states([](auto state) { std::cerr << state.c_str() << std::endl; });

  std::cout << "Welcome to tun libtcp asio laboratory.\n";
  server.run();
  return 0;
}