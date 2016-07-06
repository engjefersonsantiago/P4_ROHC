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

/* includes required to use the decompression part of the ROHC library */
#include "rohc_decompressor_module.h"

namespace ROHC {

// Create ROHC decompressor
int RohcDecompressorEntity::decompress_init(bool debug_enable)
{
	/* Create a ROHC decompressor to operate:
	 *  - with large CIDs,
	 *  - with the maximum of 5 streams (MAX_CID = 4),
	 *  - in Unidirectional mode (U-mode).
	 */

  decomp_debug_enable = debug_enable;
	if (decomp_debug_enable) printf("\ncreate the ROHC decompressor\n");

	decomp_state = rohc_decomp_new2(ROHC_LARGE_CID, 4, ROHC_U_MODE);

	if(decomp_state == NULL)
	{
	  if (decomp_debug_enable) printf("\nfailed create the ROHC decompressor\n");
	  goto error;
	}

	/* Enable Debug trace */
	if (decomp_debug_enable){ 
    if (!rohc_decomp_set_traces_cb2(decomp_state, print_rohc_traces, NULL)) {
	    if (decomp_debug_enable) printf("\nfailed to enable traces\n");
	  	goto error;	  
    }
  }

	/* Enable the decompression profiles you need */
	for (int i = 0; i <= ROHC_PROFILE_IP; i++) {
		const char *profile_name = rohc_get_profile_descr((rohc_profile_t)i); 	
	  if (decomp_debug_enable) printf("\nEnable %s ROHC decompression profile\n", profile_name);
		if(!rohc_decomp_enable_profile(decomp_state, (rohc_profile_t)i))
		{
			if (decomp_debug_enable) printf("\nfailed to enable the %s profile\n", profile_name);
			rohc_decomp_free(decomp_state);
			goto error;
		}
	}
	
	if (decomp_debug_enable) printf("\nDecompressor initialization ended successfully.\n");
	return 0;

error:
	if (decomp_debug_enable) printf("\nan error occured during program execution, abort program\n");
	return 1;
}

/**
 * @brief The main entry point for the program
 *
 * @param argc  The number of arguments given to the program
 * @param argv  The table of arguments given to the program
 * @return      0 in case of success, 1 otherwise
*/
int RohcDecompressorEntity::decompress_header(unsigned char *compressed_header_buffer, unsigned char *umcompressed_header_buffer,
						size_t comp_header_size, size_t umcomp_header_size)
{
	// Define IP and ROHC packets
	/* the buffer that will contain the ROHC packet to decompress */
	struct rohc_buf rohc_packet = rohc_buf_init_empty(compressed_header_buffer, BUFFER_SIZE);

	/* the buffer that will contain the resulting IP packet */
	struct rohc_buf ip_packet = rohc_buf_init_empty(umcompressed_header_buffer, BUFFER_SIZE);

	rohc_status_t status;
	size_t i;

	/* create a fake ROHC packet for the purpose of this program */
	if (decomp_debug_enable) printf("\nbuild a ROHC packet\n");
	for (rohc_packet.len = 0; rohc_packet.len < comp_header_size; rohc_packet.len++) {
		rohc_buf_byte_at(rohc_packet, rohc_packet.len) = compressed_header_buffer[rohc_packet.len];
	}

	/* dump the newly-created ROHC packet on terminal */
	dump_packet(rohc_packet);

	/* Now, decompress this fake ROHC packet */
	if (decomp_debug_enable) printf("\ndecompress the ROHC packet\n");
	status = rohc_decompress3(decomp_state, rohc_packet, &ip_packet, NULL, NULL); //Feedback packets not suppported
	if (decomp_debug_enable) printf("\n");
	if(status == ROHC_STATUS_OK)
	{
		/* decompression is successful */
		if(!rohc_buf_is_empty(ip_packet))
		{
 			/* ip_packet.len bytes of decompressed IP data available in
			 * ip_packet: dump the IP packet on the standard output */
			if (decomp_debug_enable) printf("packet resulting from the ROHC decompression:\n");
			dump_packet(ip_packet);
 			//for (i = 0; i < ip_packet.len; i++) {
 			for (i = 0; i < umcomp_header_size; i++) {
				umcompressed_header_buffer[i] = rohc_buf_byte_at(ip_packet, i);
			}

		}
		else
		{
			/* no IP packet was decompressed because of ROHC segmentation or
			 * feedback-only packet:
			 *  - the ROHC packet was a non-final segment, so at least another
			 *    ROHC segment is required to be able to decompress the full
			 *    ROHC packet
			 *  - the ROHC packet was a feedback-only packet, it contained only
			 *    feedback information, so there was nothing to decompress */
			if (decomp_debug_enable) printf("no packet decompressed");
		}
	}
	else
	{
		/* failure: decompressor failed to decompress the ROHC packet */
		if (decomp_debug_enable) printf("\ndecompression of fake ROHC packet failed\n");
		
		goto release_decompressor;
	}

	if (decomp_debug_enable) printf("\nThe program ended successfully.\n");

	return 0;

release_decompressor:
	rohc_decomp_free(decomp_state);
	
	if (decomp_debug_enable) printf("\nan error occured during program execution, abort program\n");
	return 1;
}

/**
 * @brief Dump the given network packet on standard output
 *
 * @param packet  The packet to dump
 */
//static void dump_packet(const struct rohc_buf packet)
void RohcDecompressorEntity::dump_packet(const struct rohc_buf packet)
{
	size_t i;

	for(i = 0; i < packet.len; i++)
	{
		if (decomp_debug_enable) printf("0x%02x ", rohc_buf_byte_at(packet, i));
		if(i != 0 && ((i + 1) % 8) == 0)
		{
			if (decomp_debug_enable) printf("\n");
		}
	}
	if(i != 0 && ((i + 1) % 8) != 0) /* be sure to go to the line */
	{
		if (decomp_debug_enable) printf("\n");
	}
}

RohcDecompressorEntity::~RohcDecompressorEntity() {
	rohc_decomp_free(decomp_state);
}

} // end namespace

