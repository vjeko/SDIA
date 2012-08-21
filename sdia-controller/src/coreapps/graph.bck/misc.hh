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

uint32_t get_random_uint32_t() {
  static boost::mt19937 randGen;
  static boost::uniform_int<uint32_t> uInt32Dist(0, std::numeric_limits<uint32_t>::max());
  static boost::variate_generator<boost::mt19937&, boost::uniform_int<uint32_t> > getRand(randGen, uInt32Dist);
  return getRand();
}

std::string ip6_addr_str(struct in6_addr addr) {
  char str[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(addr), str, INET6_ADDRSTRLEN);
  return str;
}


class dp_node {
public:

  enum NodeTypeE {
    HOST = -1,
    OPENFLOW = -2,
    SWITCH = -3
  };

  typedef uint64_t datapath_t;
  typedef uint64_t transaction_t;
  typedef uint16_t port_t;

  dp_node() {}

  dp_node(
      datapath_t datapath,
      enum NodeTypeE type = HOST,
      transaction_t transaction = 0) :
    datapath_(datapath), type_(type) {
  }

  bool operator==(const dp_node& other) const {
    bool result;

    if (datapath_ == other.datapath_) result = true;
    else result = false;

    //std::cout << datapath_ << " == " << other.datapath_ << " || " << result << std::endl;
    return result;
  }

  bool operator<(const dp_node& other) const {
    bool result;

    if (datapath_ < other.datapath_) result = true;
    else result = false;

    //std::cout << datapath_ << " < " << other.datapath_ << " || " << result << std::endl;
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
  transaction_t  transaction_;
  enum NodeTypeE type_;
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
      enum NodeTypeE type = HOST,
      transaction_t transaction = 0) :
    dp_node(datapath, type, transaction), port_(port) {
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

  const std::string print() const {
    std::ostringstream oss(std::ostringstream::out);
    oss << datapath_ << ":" << port_;
    return oss.str();
  }

};




template<class Name>
class label_writer {
public:
  label_writer(Name _name) :
    name(_name) {
  }

  template<class VertexOrEdge>
  void operator()(std::ostream& out, const VertexOrEdge& v) const {

    if (name[v].type_ ==  dp_link::OPENFLOW) {
      out << "[label=\"" << v << "\", "
          "shape=\"rectangle\",style=\"filled\",color=\"limegreen\"]";
    } else if (name[v].type_ ==  dp_link::HOST) {
      out << "[label=\"" << v << "\", "
          "shape=\"circle\",style=\"filled\",color=\"deepskyblue\"]";
    } else if (name[v].type_ ==  dp_link::SWITCH) {
      out << "[label=\""  << v << "\", "
          "shape=\"rectangle\",style=\"filled\",color=\"orange\"]";
    }

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
