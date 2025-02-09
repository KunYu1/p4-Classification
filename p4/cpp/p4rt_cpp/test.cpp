#include <iostream>

#include "google/protobuf/text_format.h"
#include "p4/config/v1/p4info.pb.h"

using ::google::protobuf::TextFormat;
using ::p4::config::v1::P4Info;

int main() {
  P4Info p4info;
  TextFormat::ParseFromString(R"PROTO(
                              tables {
                                preamble {
                                  id: 10
                                  name: "Hello, P4Runtime!"
                                }
                              }
                            )PROTO", &p4info);
  // p4info.mutable_tables()->at(0).mutable_preamble()->set_id(42);
  auto table = p4info.mutable_tables()->Get(0);
  table.mutable_preamble()->set_id(42);
  auto tables = p4info.add_tables();
  tables->set_allocated_preamble(table.mutable_preamble());
  std::cout << p4info.DebugString();
}

