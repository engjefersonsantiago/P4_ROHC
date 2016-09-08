/* Copyright 2016
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* P4 compatible extern type for ROHC header compression 
 * Jeferson Santiago da Silva (eng.jefersonsantiago@gmail.com)
 */

#include <cassert>
#include <chrono>

#include <bm/bm_sim/extern.h>
#include <rohc/rohc_compressor_module.h>

using namespace std;

template <typename... Args>
using ActionPrimitive = bm::ActionPrimitive<Args...>;

using bm::Data;
using bm::Header;
using bm::PHV;
using bm::ExternType;

using ROHC::RohcCompressorEntity;

class ExternRohcCompressor : public ExternType {
 public:

  // Attributes
  static constexpr unsigned int QUIET = 0;
  static constexpr unsigned int DEBUG_MODE = 1;

  BM_EXTERN_ATTRIBUTES {
    BM_EXTERN_ATTRIBUTE_ADD(verbose);
  }

  // Init variables
  void init() override {
    dbg_en = (bool)verbose.get<unsigned int>() == DEBUG_MODE;
    rohc_c_ent.compress_init(dbg_en);
  }

  // External ROHC compressor entity
  void rohc_comp_header () {
    std::chrono::high_resolution_clock::time_point t1 =
        std::chrono::high_resolution_clock::now();

    PHV* phv = get_packet().get_phv();
    size_t uncomp_headers_size = 0;
    size_t first_header_size = 	 0;

    // Get the headers to compress skipping the first one
    std::vector<Header*> uncomp_headers;
    bool first_header = true;
    for (auto it = phv->header_begin(); it != phv->header_end(); ++it) {
      const Header &header = *it;
      if (header.is_valid() && !header.is_metadata()) {
      	if(!first_header) {
          uncomp_headers_size += header.get_nbytes_packet();			
          uncomp_headers.push_back((Header*) &header);
        }
        else {  
          first_header = false;
          first_header_size = header.get_nbytes_packet();		
        }
      }
    }
    size_t payload_size = phv->get_field("standard_metadata.packet_length")
        .get_uint() - first_header_size - uncomp_headers_size;
    size_t comp_header_size = 0;

    unsigned char *uncomp_buff = new unsigned char [uncomp_headers_size];
    unsigned char *comp_buff = new unsigned char [uncomp_headers_size
                                                  + payload_size + 2];

    // Initialize the compression data structures 
    int index_comp_buff = 0;
    for(auto h : uncomp_headers) {
      for (size_t f = 0; f < h->size(); ++f) {
    	  const char* data = h->get_field(f).get_bytes().data();
  	    for (int i = 0; i < (int) h->get_field(f).get_bytes().size(); ++i) {
  	      uncomp_buff[index_comp_buff] = *data;
  	      ++index_comp_buff;
          ++data;
        }
      }
      // Mark headers invalid so they won't be serialized
      h->mark_invalid();
    }

    // Perform the header decompression
    rohc_c_ent.compress_header(
        comp_buff,
        uncomp_buff,
        &comp_header_size, 
        (size_t) uncomp_headers_size + payload_size);

    comp_header_size -= payload_size;

    // Positionate the head of the buffer to put the compressed header
    // inside the payload
    char *payload_start = get_packet().prepend(comp_header_size);
    // Overwrite the packet headers with the compressed one
    for (int i = 0; i < (int)comp_header_size; ++i){
      payload_start[i] = comp_buff[i];
    }

    std::chrono::high_resolution_clock::time_point t2 = 
        std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>
        (t2 - t1).count();
    cout << "Compression execution time: " << duration << " useconds\n";

  }

  // Default constructor/destructor
  virtual ~ExternRohcCompressor () {}
  
 private:
  // declared attributes
  Data verbose{DEBUG_MODE};
  
  // Stateful parameters
  bool dbg_en{true};
  RohcCompressorEntity rohc_c_ent;

};

BM_REGISTER_EXTERN(ExternRohcCompressor);
BM_REGISTER_EXTERN_METHOD(ExternRohcCompressor, rohc_comp_header);

constexpr unsigned int ExternRohcCompressor::QUIET;
constexpr unsigned int ExternRohcCompressor::DEBUG_MODE;

// End Declaration

int import_rohc_comp() {
  return 0;
}
