/*
 * Copyright 2013,2014 Didier Barvaux
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
 */

/**
 * @file     example_rohc_decomp.c
 * @brief    A program that uses the decompression part of the ROHC library
 * @author   Didier Barvaux <didier@barvaux.org>
 */

/**
 * @example example_rohc_decomp.c
 *
 * How to decompress one ROHC packet into one IP packet.
 */

#ifndef ROHC_DECOMP_MODULE_H
#define ROHC_DECOMP_MODULE_H

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

/* includes required to use the decompression part of the ROHC library */
#include "../src/common/rohc.h"
#include "../src/decomp/rohc_decomp.h"
#include "../src/common/rohc_traces.h"

/** The size (in bytes) of the buffers used in the program */
#define BUFFER_SIZE 2048

namespace ROHC {

class RohcDecompressorEntity {
  bool debug_en;

	public:
		/* Prototypes */
		void dump_packet(const struct rohc_buf packet);
		int decompress_init(bool debug_enable);
		int decompress_header(unsigned char *compressed_header_buffer,
                          unsigned char *umcompressed_header_buffer,
								          size_t comp_header_size,
                          size_t umcomp_header_size);

		virtual ~RohcDecompressorEntity();

    RohcDecompressorEntity (bool en) : debug_en(en) {} 

	private:
		// define ROHC decompressor
		// There is a best way to keep the state of the compressor instead declaring it as global?
		struct rohc_decomp *decomp_state;       /* the ROHC decompressor */
    int init_status = decompress_init(debug_en);
    bool decomp_debug_enable = debug_en;
    static void print_rohc_traces(void *const priv_ctxt __attribute__((unused)),
		                              const rohc_trace_level_t level,
		                              const rohc_trace_entity_t entity __attribute__((unused)),
		                              const int profile __attribute__((unused)),
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

};

} //namespace

#ifdef __cplusplus
}
#endif

#endif /* ROHC_DECOMP_MODULE_H */

