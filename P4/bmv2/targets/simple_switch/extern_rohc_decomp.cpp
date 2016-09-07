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

/* P4 compatible extern type for ROHC header decompression 
 * Jeferson Santiago da Silva (eng.jefersonsantiago@gmail.com)
 */

#include <cassert>
#include <chrono>

#include <bm/bm_sim/extern.h>
#include <rohc/rohc_decompressor_module.h>

// Used to define enough space to extract the compressed header to the uncomp_buffer
#define EXTRA_LENGHT_UNCOMP 80

using namespace std;

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
using ROHC::RohcDecompressorEntity;

class ExternRohcDecompressor : public ExternType {
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
    rohc_d_ent.decompress_init(dbg_en);
  }

  // Decompressor primitive
  void rohc_decomp_header() {
    std::chrono::high_resolution_clock::time_point t1 =
        std::chrono::high_resolution_clock::now();   
    
    // Calculate the size of all real header (not metadata) except the first one
    PHV* phv = get_packet().get_phv();
    std::vector<Header*> extracted_headers;
    size_t headers_size = 0;
    for (auto it = phv->header_begin(); it != phv->header_end(); ++it) {
      const Header &header = *it;
      if (header.is_valid() && !header.is_metadata()) {
        extracted_headers.push_back((Header*) &header);
        headers_size += header.get_nbytes_packet();
      }
    }
    
    size_t comp_header_size = phv->get_field("standard_metadata.packet_length")
        .get_uint() - headers_size;
    size_t uncomp_header_size = 0;
    unsigned char *comp_buff = new unsigned char [comp_header_size];
    unsigned char *uncomp_buff = new unsigned char [comp_header_size + 
                                                    EXTRA_LENGHT_UNCOMP];
    
    // Initialize the decompression data structures 
    int index_comp_buff = 0;
    const char *c = get_packet().prepend(0);
    for (int i = 0; i < (int) comp_header_size ; ++i) {
      comp_buff[index_comp_buff] = *c;
      ++index_comp_buff;
      ++c;
    }
    
    // Perform the header decompression
    rohc_d_ent.decompress_header(comp_buff,
                                 uncomp_buff,
                                 (size_t) comp_header_size,
                                 &uncomp_header_size);
    
    // Remove the compressed header inside the payload
    get_packet().remove(comp_header_size);
    // Positionate the head of the buffer to put the uncompressed 
    // header inside the payload
    char *payload_start = get_packet().prepend(uncomp_header_size);
    // Overwrite the packet headers with the uncompressed one
    for (int i = 0; i < (int) uncomp_header_size; ++i)
      payload_start[i] = uncomp_buff[i];	
    
    for (int i = extracted_headers.size() - 1; i >= 0; --i) {
      payload_start = get_packet().prepend(extracted_headers[i]->
          get_nbytes_packet());			
      extracted_headers[i]->deparse(payload_start);
      extracted_headers[i]->mark_invalid();
    }
    
    std::chrono::high_resolution_clock::time_point t2 = 
        std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>
        (t2 - t1).count();
    cout << "Decompression execution time: " << duration << " useconds\n";
 
  }

  // Default constructor/destructor
  virtual ~ExternRohcDecompressor () {}
  
 private:
  // declared attributes
  Data verbose{DEBUG_MODE};
  
  // Stateful parameters
  bool dbg_en{true};
  RohcDecompressorEntity rohc_d_ent;

};

BM_REGISTER_EXTERN(ExternRohcDecompressor);
BM_REGISTER_EXTERN_METHOD(ExternRohcDecompressor, rohc_decomp_header);

constexpr unsigned int ExternRohcDecompressor::QUIET;
constexpr unsigned int ExternRohcDecompressor::DEBUG_MODE;

// End Declaration

int import_rohc_decomp() {
  return 0;
}
