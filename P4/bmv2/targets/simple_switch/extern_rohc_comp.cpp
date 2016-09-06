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

template <typename... Args>
using ActionPrimitive = bm::ActionPrimitive<Args...>;

using bm::Data;
using bm::Field;
using bm::Header;
using bm::MeterArray;
using bm::CounterArray;
using bm::RegisterArray;
using bm::NamedCalculation;
using bm::HeaderStack;
using bm::PHV;
using bm::ExternType;
using bm::ActionFnEntry;
using bm::ActionFn;
using bm::ActionPrimitive_;
using bm::ActionOpcodesMap;
using bm::P4Objects;
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
    printf("Here 1\n");
    dbg_en = (bool)verbose.get<unsigned int>() == DEBUG_MODE;
    printf("Here 2\n");
    init_done = true;
    //if (!init_done)
      rohc_c_ent.compress_init(dbg_en);
    printf("Here 3\n");
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

    printf("Uncompressed packet:\n");
    for (size_t i = 0; i < uncomp_headers_size; ++i) 
      printf("0x%.2x ", uncomp_buff[i]);
    printf("\n");
    
    // Perform the header decompression
    rohc_c_ent.compress_header(
        comp_buff,
        uncomp_buff,
        &comp_header_size, 
        (size_t) uncomp_headers_size + payload_size);

    comp_header_size -= payload_size;

    printf("Compressed packet:\n");
    printf("N Bytes: %d\n", (int) comp_header_size);
    for (size_t i = 0; i < comp_header_size; ++i) 
      printf("0x%.2x ", comp_buff[i]);
    printf("\n");
  
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
    printf("Compression execution time: %lu useconds\n", (uint64_t) duration);

  }

  // Default constructor/destructor
  virtual ~ExternRohcCompressor () {}
  
 private:
  // declared attributes
  Data verbose{DEBUG_MODE};
  
  // Stateful parameters
  bool dbg_en{true};
  RohcCompressorEntity rohc_c_ent;// = {false, false};
  bool init_done = false;

};

BM_REGISTER_EXTERN(ExternRohcCompressor);
BM_REGISTER_EXTERN_METHOD(ExternRohcCompressor, rohc_comp_header);

constexpr unsigned int ExternRohcCompressor::QUIET;
constexpr unsigned int ExternRohcCompressor::DEBUG_MODE;

// End Declaration

int import_rohc_comp() {
  return 0;
}
