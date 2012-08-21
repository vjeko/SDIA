/*
 * misc.hh
 *
 *  Created on: 2010-05-24
 *      Author: vjeko
 */

#ifndef MISC_HH_
#define MISC_HH_

#include <iostream>
#include <string>
#include <sstream>
#include <arpa/inet.h>

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>
#include <boost/asio.hpp>
#include <list>

#include "protobuf/interface.pb.h"


template<class Size>
uint32_t get_random(Size min = 0, Size max = std::numeric_limits<Size>::max()) {

  static boost::mt19937 randGen;
  static boost::uniform_int<Size> uInt32Dist(min, max);
  static boost::variate_generator<boost::mt19937&, boost::uniform_int<Size> > getRand(randGen, uInt32Dist);
  randGen.seed(static_cast<unsigned int>(std::time(0)));
  return getRand();
}

std::string ip6_addr_str(struct in6_addr addr) {
  char str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(addr), str, INET6_ADDRSTRLEN);
  return str;
}



using boost::asio::ip::tcp;

class graph;

class session {

public:
  session(boost::asio::io_service& io_service, graph* const g);
  tcp::socket& socket();

  void start();
  void handle_read(const boost::system::error_code& error, size_t bytes_transferred);
  void handle_read_size(const boost::system::error_code& error, size_t bytes_transferred);
  void handle_write(const boost::system::error_code& error, const uint8_t* data, size_t size);
  void write(const uint8_t* data, size_t size);
  void write(::RPC& rpc);

  void handlePacketInResponse(RPC& rpc);
  void andleDataPush(RPC& rpc);
  void handleInitRequest(RPC& rpc);

  tcp::socket socket_;
  enum { max_length = 10240 };
  boost::array<char, max_length> data_;
  boost::array<int32_t, 1> len_;
  graph* const graph_;
};


class server {

public:
  server(
      boost::asio::io_service& io_service,
      const uint16_t port,
      graph* const graph_);

  std::list< boost::shared_ptr<session> > sessions_;

  void handle_accept(
      boost::shared_ptr<session> new_session,
      const boost::system::error_code& error);
  void start_accept();


private:
  boost::asio::io_service& io_service_;
  tcp::acceptor acceptor_;
  graph* const graph_;
};


class dp_node {
public:

  enum NodeTypeE {
    HOST = -1,
    OPENFLOW = -2,
    SWITCH = -3,
    OTHER_DOMAIN = -4
  };

  typedef uint64_t datapath_t;
  typedef uint64_t transaction_t;
  typedef uint16_t port_t;

  dp_node() {}

  dp_node(
      datapath_t datapath,
      uint64_t domain = 0,
      enum NodeTypeE type = HOST) :
        datapath_(datapath), opposite_(0), type_(type), domain_(domain) {
  }


  bool operator==(const dp_node& other) const {
    bool result;

    if (datapath_ == other.datapath_) result = true;
    else result = false;
    return result;
  }


  bool operator<(const dp_node& other) const {
    bool result;

    if (datapath_ < other.datapath_) result = true;
    else result = false;
    return result;
  }


  datapath_t get_datapath() const {
    return datapath_;
  }

  NodeTypeE get_type() const {
    return type_;
  }

  struct HashStruct {
    size_t operator()(const dp_node& a) const {
      return a.datapath_;
    }
  };

  const std::string print() const {
    std::ostringstream oss(std::ostringstream::out);
    oss << datapath_;
    return oss.str();
  }

  in6_addr       ip6_addr_;
  datapath_t     datapath_;
  datapath_t     opposite_;
  enum NodeTypeE type_;
  uint64_t       domain_;

};



class dp_link : public dp_node {
public:

  enum {
    HOST_PORT = 0
  };

  dp_link() {}

  dp_link(
      datapath_t datapath,
      port_t port,
      uint64_t domain,
      enum NodeTypeE type = HOST) :
    dp_node(datapath, domain, type), port_(port) {
  }

  bool operator==(const dp_link& other) const {
    if ((datapath_ == other.datapath_) 
      && (port_ == other.port_)) return true;
    else return false;
  }


  bool operator<(const dp_link& other) const {

    if (datapath_ < other.datapath_) return true;

    if (datapath_ == other.datapath_) {
      if (port_ < other.port_) return true;
    }

    return false;
  }


  port_t get_port() {
    return port_;
  }


  struct HashStruct {
    size_t operator()(const dp_link& a) const {
      return a.datapath_ + a.port_;
    }
  };


  port_t port_;
};




template<class Name>
class label_writer {
public:
  label_writer(Name _name) :
    name(_name) {
  }

  template<class VertexOrEdge>
  void operator()(std::ostream& out, const VertexOrEdge& v) const {

    out << " [ "
        << "type = " << name[v].type_ << ", "
        << "domain = " << name[v].domain_ << ", "
        << " ] ";
  }

  void operator()(std::ostream& out) const {
    out << "graph [bgcolor=lightgrey]" << std::endl;
    out << "node [shape=circle color=white]" << std::endl;
    out << "edge [style=dashed]" << std::endl;
  }



private:

  Name& name;
};


#endif /* MISC_HH_ */
