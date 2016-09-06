/*
 * Copyright 2016
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Jeferson Santiago da Silva and Laurent Olivier Chiquette
 *
 */

#ifndef ROHC_COMP_MODULE_H
#define ROHC_COMP_MODULE_H

#ifdef __cplusplus
extern "C"
{
#endif

/* system includes */
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <netinet/in.h>

/* includes required to use the compression part of the ROHC library */
#include <rohc/rohc.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_traces.h>

/** The size (in bytes) of the buffers used in the program */
#define BUFFER_SIZE 2048

namespace ROHC {

class RohcCompressorEntity {
  bool default_start, debug_en;
 public:
  /* Prototypes */
  void dump_packet(const struct rohc_buf packet);
  int compress_init(bool debug_enable);
  int compress_header(unsigned char *compressed_header_buffer,
                       unsigned char *uncompressed_header_buffer,
  						        size_t *comp_header_size,
                       size_t uncomp_header_size);
  
  bool get_comp_status () {
    return init_status == 0;
  }

  virtual ~RohcCompressorEntity();	
  RohcCompressorEntity (bool start = false, bool dbg_en = false)
      : default_start(start), debug_en(dbg_en) {} 

 private:
 	// define ROHC compressor
 	// There is a best way to keep the state of the compressor
   // instead declaring it as global?
  struct rohc_comp *comp_state;       /* the ROHC compressor */
  int init_status = (default_start) ? compress_init(debug_en) : -1;
  bool comp_debug_enable = debug_en;
 	
  static void print_rohc_traces(void *const priv_ctxt
                                                        __attribute__((unused)),
 	                              const rohc_trace_level_t level,
 	                              const rohc_trace_entity_t entity
                                                        __attribute__((unused)),
 	                              const int profile
                                                        __attribute__((unused)),
 	                              const char *const format,
 	                              ...)
 	{
 		const char *level_descrs[] =
 		{
 			[ROHC_TRACE_DEBUG]   = "DEBUG",
 			[ROHC_TRACE_INFO]    = "INFO",
 			[ROHC_TRACE_WARNING] = "WARNING",
 			[ROHC_TRACE_ERROR]   = "ERROR"
 		};
 		va_list args;
 		
    fprintf(stdout, "[%s] ", level_descrs[level]);
    va_start(args, format);
    vfprintf(stdout, format, args);
 		va_end(args);
 	}
   
  static int gen_false_random_num(const struct rohc_comp *const comp
                                                        __attribute__((unused)),
                                  void *const user_context 
                                                        __attribute__((unused)))
  {
    return rand()%4;
  }
 
  static bool rohc_comp_rtp_cb(const unsigned char *const ip
                                                        __attribute__((unused)),
                               const unsigned char *const udp,
                               const unsigned char *const payload
                                                        __attribute__((unused)),
                               const unsigned int payload_size
                                                        __attribute__((unused)),
                               void *const rtp_private
                                                        __attribute__((unused)))
  {
   	const size_t default_rtp_ports_nr = 6;
   	unsigned int default_rtp_ports[] = { 1234, 36780, 33238, 5020, 5002, 5006 };
   	uint16_t udp_dport;
   	bool is_rtp = false;
   	size_t i;
   
   	if(udp == NULL)
   	{
   		return false;
   	}
   
   	/* get the UDP destination port */
   	memcpy(&udp_dport, udp + 2, sizeof(uint16_t));
   
   	/* is the UDP destination port in the list of ports reserved for RTP
   	 * traffic by default (for compatibility reasons) */
   	for(i = 0; i < default_rtp_ports_nr; i++)
   	{
   	  if(ntohs(udp_dport) == default_rtp_ports[i])
   		{
   	    is_rtp = true;
   	    break;
   	  }
   	}
   
   	return is_rtp;
  }

};

} //namespace

#ifdef __cplusplus
}
#endif

#endif /* ROHC_COMP_MODULE_H */

