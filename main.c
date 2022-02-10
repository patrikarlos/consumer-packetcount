/***************************************************************************
                          main.c  -  description
                             -------------------
    begin                : Fri Jan 31 2003
    copyright            : (C) 2003 by Anders Ekberg anders.ekberg@bth.se
	                   (C) 2012 Vamsi Krishna Konakalla <xvk@bth.se>\n");
	                   (C) 2012 David Sveningsson <david.sveningsson@bth.se>\n\n");
                           (C) 2021 Patrik Arlos patrik.arlos@bth.se

***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <caputils/caputils.h>
#include <caputils/stream.h>
#include <caputils/filter.h>
#include <caputils/utils.h>
#include <caputils/log.h>
#include <caputils/packet.h>

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>

#define VERSION "2"

typedef void (*format_func)(const timepico* time, const timepico* delta);
static format_func formatter = NULL;         // output formatter
static const char* program_name;             // this programs name
static const char *iface = NULL;             // ethernet iface (used only when using ethernet multicast)
static unsigned long int max_packets = 0;    // stop after N packets
static int noheader = 0;                     // If non-zero no format header is written
static int nooffset = 0;                     // If non-zero no time offset it used
static int keep_running = 1;
static int showpacket=0;
static unsigned int flags = FORMAT_REL_TIMESTAMP;

static const char* shortopts = "hi:p:cS" "i:p:cSdDar1234xHh";
static struct option long_options[]= {
	{"pkts",   required_argument, 0, 'p'},
	{"iface",  required_argument, 0, 'i'},
	{"format", required_argument, 0, 'f'},
	{"no-header", no_argument,    0, '0'},
	{"no-offset", no_argument,    0, 'x'},
	{"help",   no_argument,       0, 'h'},
	{"display-packet", no_argument,0, 'S'},
	{"verbose", no_argument,0, 'v'},

	{"calender", no_argument,       0, 'd'},
	{"localtime",no_argument,       0, 'D'},
	{"absolute", no_argument,       0, 'a'},
	{"relative", no_argument,       0, 'r'},
	{"hexdump",  no_argument,       0, 'x'},
	{"headers",  no_argument,       0, 'H'},

	
	{0, 0, 0, 0} /* sentinel */
};

static void show_usage(void){
	printf("%s-" VERSION " (libcap_utils-" CAPUTILS_VERSION ")\n", program_name);
	printf("(C) 2003 Anders Ekberg <anders.ekberg@bth.se>\n");
	printf("(C) 2012 Vamsi Krishna Konakalla <xvk@bth.se>\n");
	printf("(C) 2012 David Sveningsson <david.sveningsson@bth.se>\n\n");
	printf("(C) 2021 Patrik Arlos <patrik.arlos@bth.se>\n\n");
	printf("Usage: %s [OPTIONS] STREAM\n"
	       "  -p, --pkts=INT         Number of pkts to show [default all]\n"
	       "  -i, --iface=IFACE      Use ethernet interface IFACE\n"
	       "  -f, --format=FORMAT    Set output FORMAT. Valid format is csv and default.\n"
	       "  -c                     Short for --format=csv\n"
	       "      --no-header        Don't write format header.\n"
	       "      --no-offset        Don't use a time offset.\n"
	       "  -d, --display-packet  Show packet information.\n"
	       "  -h, --help             This text\n"
	       "  -v, --verbose          Be verbose in output.\n"
	       "\n"
	       "Formatting options:\n"
	       "  -1                   Show only DPMI information.\n"
	       "  -2                     .. include link layer.\n"
	       "  -3                     .. include transport layer.\n"
	       "  -4                     .. include application layer. [default]\n"
	       "  -H, --headers        Show layer headers.\n"
	       "  -x, --hexdump        Write full packet content as hexdump.\n"
	       "  -d, --calender       Show timestamps in human-readable format (UTC).\n"
	       "  -D, --localtime      Show timestamps in human-readable format (local time).\n"
	       "  -a, --absolute       Show absolute timestamps.\n"
	       "  -r, --relative       Show timestamps relative to first packet. [default]\n"
	       
	       "Recommended conserver usage:\n"
	       "%s -c | conserver -j1 -n NAME\n"
	       "\n", program_name, program_name);
	filter_from_argv_usage();
}


struct tg_Protocol {
  u_int32_t exp_id;// Experiment ID
  u_int32_t run_id;// Run ID
  u_int32_t key_id;// Key ID
  u_int32_t counter;// Packet Counter
  u_int64_t starttime;// Start of packet transmission time, comes with packet.counter+1
  u_int64_t stoptime;// Stopt of packet transmission time,  comes with packet.counter+1
  struct timeval depttime; // Departure time. 
  u_int64_t recvstarttime; // Receive start and stop time, recorded at receiver.
  u_int64_t recvstoptime; // Receive start and stop time, recorded at receiver.
  struct timeval recvtime;// Receive time
  // After this comes the payload. 
};

static void handle_sigint(int signum){
	if ( keep_running == 0 ){
		fprintf(stderr, "\r%s: got SIGINT again, aborting\n", program_name);
		abort();
	} else {
		fprintf(stderr, "\r%s: got SIGINT, terminating\n", program_name);
		keep_running = 0;
	}
}

static void default_formatter(const timepico* time, const timepico* delta){
	fprintf(stdout, "%d.%012"PRIu64" %d.%012"PRIu64" ", time->tv_sec, time->tv_psec, delta->tv_sec, delta->tv_psec);
}

static void csv_formatter(const timepico* time, const timepico* delta){
	fprintf(stdout, "%d.%012"PRIu64";%d.%012"PRIu64";", time->tv_sec, time->tv_psec, delta->tv_sec, delta->tv_psec);	

}

int main (int argc, char **argv){
	/* extract program name from path. e.g. /path/to/MArCd -> MArCd */
	const char* separator = strrchr(argv[0], '/');
	if ( separator ){
		program_name = separator + 1;
	} else {
		program_name = argv[0];
	}

	struct filter filter;                 // filter to filter arguments
	stream_t stream;                      // stream to read from
	formatter = default_formatter;

	int quiet=1;
	
	/* Create filter from command line arguments */
	if ( filter_from_argv(&argc,argv, &filter) != 0) {
		fprintf(stderr, "%s: could not create filter", program_name);
		return 1;
	}

	/* Parse command line arguments (filter arguments has been consumed) */
	int op, option_index;
	while ( (op = getopt_long(argc, argv, shortopts, long_options, &option_index)) != -1 ){
		switch ( op ){
		case 0:   /* long opt */       
		case '?': /* unknown opt */
			break;

		case '1':
		case '2':
		case '3':
		case '4':
		{
			const unsigned int mask = (7<<FORMAT_LAYER_BIT);
			flags &= ~mask; /* reset all layer bits */
			flags |= (op-'0')<<FORMAT_LAYER_BIT;
			break;
		}
	    
		case 'd': /* --calender */
			flags |= FORMAT_DATE_STR | FORMAT_DATE_UTC;
			break;

		case 'D': /* --localtime */
			flags |= FORMAT_DATE_STR | FORMAT_DATE_LOCALTIME;
			break;

		case 'a': /* --absolute */
			flags &= ~FORMAT_REL_TIMESTAMP;
			break;

		case 'r': /* --relative */
			flags |= FORMAT_REL_TIMESTAMP;
			break;

		case 'H': /* --headers */
			flags |= FORMAT_HEADER;
			break;

			
		case 'i': /* --iface */
			iface = optarg;
			break;

		case 'p': /* --pkts */
			max_packets = atoi(optarg);
			break;

		case 'f': /* --format */
			if ( strcasecmp(optarg, "csv") == 0 ){
				formatter = csv_formatter;
			} else if ( strcasecmp(optarg, "default") == 0 ){
				formatter = default_formatter;
			} else {
				fprintf(stderr, "%s: unknown output format `%s'\n", program_name, optarg);
				return 1;
			}
			break;

		case 'c': /* --format=csv */
			formatter = csv_formatter;
			break;

		case '0': /* --no-header */
			noheader = 1;
			break;

		case 'x': /* --no-offset */
			nooffset = 1;
			break;

		case 'v': /* Verbose */
   		        quiet=0;
			break;
		case 'S': /* show packet */
		        showpacket=1;
			break;
		case 'h':
			show_usage();
			return 0;

		default:
			printf ("?? getopt returned character code 0%o ??\n", op);
		}
	}

	/* No stream address was passed */
	if ( optind == argc ){
		fprintf(stderr, "No stream address was specified\n");
		show_usage();
		return 1;
	}

	/* Open stream */
	int ret;
	if ( (ret=stream_from_getopt(&stream, argv, optind, argc, iface, "-", program_name, 0)) != 0) {
		return 1;
	}
	const struct stream_stat* stat  = stream_get_stat(stream);

	/* show info about stream */
	if (quiet==0) {
	  stream_print_info(stream, stderr);
	}

	/* setup signal handler for ctrl-c */
	signal(SIGINT, handle_sigint);

	/* read initial packet to initialize variables */
	cap_head* caphead;
	if ( (ret=stream_read (stream, &caphead, &filter, NULL)) != 0 ){
		fprintf(stderr, "%s: stream_read() failed: %s\n", program_name, caputils_error_string(ret));
		return 1;
	}

	
	int packetCount=0;
	int packetVolume=0;

	/* setup formatter */
	struct format format;
	format_setup(&format, flags);

	timepico time_offset = {caphead->ts.tv_sec, 0};
	timepico last = {0, caphead->ts.tv_psec};
	char last_CI[8] = {0,};

	if ( nooffset ){
		time_offset.tv_sec = 0;
		last.tv_sec = caphead->ts.tv_sec;
	}

	packetCount++;
	packetVolume+=caphead->len;

	if (showpacket){
	  if ( filter_match(&filter, caphead->payload, caphead) ){
	    format_pkg(stdout, &format, caphead);
	  } else {
	    format_ignore(stdout, &format, caphead);
	  }
	} else {
	  // fprintf(stdout, "\n");
	}
	
	//	fprintf(stderr, "%s: Using time offset %d.%012"PRIu64".\n", program_name, time_offset.tv_sec, time_offset.tv_psec);

	/* write header */
	if ( !noheader ){
		if ( formatter == csv_formatter ){
			fprintf(stdout, "\"timestamp\";\"interarrivaltime\"\n"); /* column names */
		}
	}

	while (keep_running){
		/* read next packet */
		switch ( (ret=stream_read(stream, &caphead, &filter, NULL)) ){
		case -1:     /* eof */
			keep_running = 0;
		case EAGAIN: /* timeout */
		case EINTR:  /* call interrupted (by a signal for instance) */
			continue;
		case 0:      /* a packet was read */
			break;
		default:     /* an error has occured */
			fprintf(stderr, "%s: stream_read() failed: %s\n", program_name, caputils_error_string(ret));
			break;
		}

		timepico cur = timepico_sub(caphead->ts, time_offset);
		timepico delta = timepico_sub(cur, last);

		packetCount++;
		packetVolume+=caphead->len;
		

		if (showpacket){
		  if ( filter_match(&filter, caphead->payload, caphead) ){
		    format_pkg(stdout, &format, caphead);
		  } else {
		    format_ignore(stdout, &format, caphead);
		  }
		} else {
		  // fprintf(stdout, "\n");
		}
		last = cur;
		memcpy(last_CI, caphead->nic, 8);

		if( max_packets > 0 && stat->matched >= max_packets ) {
			break; /* Read enough pkts lets break. */
		}
	}
	if (quiet==0){
	  fprintf(stderr, "%s: There was a total of %'"PRIu64" packets read.\n", program_name, stat->read);
	  fprintf(stderr, "%s: There was a total of %'"PRIu64" packets matching filter.\n", program_name, stat->matched);
	}
	printf("PACKETS:%d\n",packetCount);
	printf("VOLUME:%d\n",packetVolume);
	stream_close(stream);
	filter_close(&filter);

	return 0;
}
