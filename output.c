#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <netdb.h>
#include "acarsdec.h"

extern int inmode;

typedef struct {
	unsigned char mode;
	unsigned char addr[8];
	unsigned char ack;
	unsigned char label[3];
	unsigned char bid;
	unsigned char bs, be;
	unsigned char txt[250];
	int err, lvl;
} acarsmsg_t;

static int sockfd = -1;
static FILE *fdout;

int initOutput(char *logfilename, char *Rawaddr)
{
	char *addr;
	char *port;
	struct addrinfo hints, *servinfo, *p;
	int rv;

	if (logfilename) {
		fdout = fopen(logfilename, "a+");
		if (fdout == NULL) {
			fprintf(stderr, "Could not open : %s\n", logfilename);
			return -1;
		}
	} else
		fdout = stdout;

	if (Rawaddr == NULL)
		return 0;

	memset(&hints, 0, sizeof hints);
	if (Rawaddr[0] == '[') {
		hints.ai_family = AF_INET6;
		addr = Rawaddr + 1;
		port = strstr(addr, "]");
		if (port == NULL) {
			fprintf(stderr, "Invalid IPV6 address\n");
			return -1;
		}
		*port = 0;
		port++;
		if (*port != ':')
			port = "13963";
		else
			port++;
	} else {
		hints.ai_family = AF_UNSPEC;
		addr = Rawaddr;
		port = strstr(addr, ":");
		if (port == NULL)
			port = "13963";
		else {
			*port = 0;
			port++;
		}
	}

	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(addr, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "Invalid/unknown address %s\n", addr);
		return -1;
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd =
		     socket(p->ai_family, p->ai_socktype,
			    p->ai_protocol)) == -1) {
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			continue;
		}
		break;
	}
	if (p == NULL) {
		fprintf(stderr, "failed to connect\n");
		return -1;
	}

	freeaddrinfo(servinfo);

	return 0;
}

static void printdate(time_t t)
{
	struct tm *tmp;

	if (t == 0)
		return;

	tmp = gmtime(&t);

	fprintf(fdout, "%02d/%02d/%04d %02d:%02d:%02d",
		tmp->tm_mday, tmp->tm_mon + 1, tmp->tm_year + 1900,
		tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
}

static void printtime(time_t t)
{
	struct tm *tmp;

	tmp = gmtime(&t);

	fprintf(fdout, "%02d:%02d:%02d",
		tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
}

void outpp(acarsmsg_t * msg)
{
	char pkt[500];
	char txt[250];
	char *pstr;

	strcpy(txt, msg->txt);
	for (pstr = txt; *pstr != 0; pstr++)
		if (*pstr == '\n' || *pstr == '\r')
			*pstr = ' ';

	sprintf(pkt, "AC%1c %7s %1c %2s %1c %s",
		msg->mode, msg->addr, msg->ack, msg->label, msg->bid, txt);

	write(sockfd, pkt, strlen(pkt));
}

void outsv(acarsmsg_t * msg, int chn, time_t tm)
{
	char pkt[500];
	struct tm *tmp;

	tmp = gmtime(&tm);

	sprintf(pkt,
		"%8s %1d %02d/%02d/%04d %02d:%02d:%02d %1d %03d %1c %7s %1c %2s %1c %s",
		idstation, chn + 1, tmp->tm_mday, tmp->tm_mon + 1,
		tmp->tm_year + 1900, tmp->tm_hour, tmp->tm_min, tmp->tm_sec,
		msg->err, msg->lvl, msg->mode, msg->addr, msg->ack, msg->label,
		msg->bid, msg->txt);

	write(sockfd, pkt, strlen(pkt));
}

#define STATION_ID_LENGTH 8

typedef struct _acars_udp_message_header_t acars_udp_message_header_t;
struct _acars_udp_message_header_t {
    char station_id[STATION_ID_LENGTH];
    unsigned int fc;
    unsigned int timestamp;
};

typedef struct _acars_udp_message_t acars_udp_message_t;
struct _acars_udp_message_t {
    acars_udp_message_header_t header;
    char payload[256];
};

void outraw(const msgblk_t * blk, int chn, time_t tm)
{
	acars_udp_message_t msg = {0};

	strncpy(&msg.header.station_id[0], &idstation[0], STATION_ID_LENGTH);
	msg.header.timestamp = htonl(tm);
	msg.header.fc = htonl((unsigned)(channel[chn].Fr / 1000.0));
	memcpy(&msg.payload[0], &blk->txt[0], blk->len);

	write(sockfd, &msg, sizeof(msg.header) + blk->len);
}


static void printmsg(acarsmsg_t * msg, int chn, time_t t)
{
#if defined (WITH_RTL) || defined (WITH_AIR)
	if (inmode >= 3)
		fprintf(fdout, "\n[#%1d (F:%3.3f L:%4d E:%1d) ", chn + 1,
			channel[chn].Fr / 1000000.0, msg->lvl, msg->err);
	else
#endif
		fprintf(fdout, "\n[#%1d ( L:%4d E:%1d) ", chn + 1, msg->lvl, msg->err);
	if (inmode != 2)
		printdate(t);
	fprintf(fdout, " --------------------------------\n");
	fprintf(fdout, "Mode : %1c ", msg->mode);
	fprintf(fdout, "Label : %2s ", msg->label);
	if(msg->bid) {
		fprintf(fdout, "Id : %1c ", msg->bid);
		if(msg->ack==0x15) fprintf(fdout, "Nak\n"); else fprintf(fdout, "Ack : %1c\n", msg->ack);
		fprintf(fdout, "Aircraft reg: %s ", msg->addr);
	}
	fprintf(fdout, "\n");
	if(msg->txt[0]) fprintf(fdout, "%s\n", msg->txt);
	if (msg->be == 0x17) fprintf(fdout, "ETB\n");

	fflush(fdout);
}

static void printbinarystringasjson(unsigned char* start,unsigned char* end)
{
	unsigned char* pos;
	char special=0;
	for (pos=start;pos<end;pos++)
	{
		unsigned char ch=*pos;
		if (ch==0) {
			end=pos;
			break;
		}
		else {
			switch (ch)
			{
			case '\\':
			case '/':
			case '\b':
			case '\f':
			case '\n':
			case '\r':
			case '\t':
				break;
			default:
				if ((ch<32)||(ch>=127))
				{
					special=1;
				}
				break;
			}
		}
	}
	if (special)
	{
		fprintf(fdout, "[");
		for (pos=start;pos<end;pos++)
		{
			if (pos!=start) fprintf(fdout, ",");
			fprintf(fdout, "%d",*pos);
		}
		fprintf(fdout, "]");
	}
	else
	{
		fprintf(fdout, "\"");
		for (pos=start;pos<end;pos++)
		{
			unsigned char ch=*pos;
			switch (ch)
			{
			case '\\':
				fprintf(fdout, "\\\\");
				break;
			case '/':
				fprintf(fdout, "\\/");
				break;
			case '\b':
				fprintf(fdout, "\\b");
				break;
			case '\f':
				fprintf(fdout, "\\f");
				break;
			case '\n':
				fprintf(fdout, "\\n");
				break;
			case '\r':
				fprintf(fdout, "\\r");
				break;
			case '\t':
				fprintf(fdout, "\\t");
				break;
			default:
				fprintf(fdout, "%c", ch);
				break;
			}
		}
		fprintf(fdout, "\"");
	}
}

#define PRINTC(X) printbinarystringasjson(&(X),&(X)+1)
#define PRINTS(X) printbinarystringasjson(&(X)[0],&(X)[0]+sizeof(X))

static void printjson(acarsmsg_t * msg, int chn, time_t t)
{
	fprintf(fdout,"{\"timestamp\":%lf,\"channel\":%d,\"level\":%d,\"error\":%d", (double)t, chn, msg->lvl, msg->err);
	fprintf(fdout,",\"mode\":");
	PRINTC(msg->mode);
	fprintf(fdout,",\"label\":");
	PRINTS(msg->label);
	if(msg->bid) {
		fprintf(fdout, ",\"block_id\":");
		PRINTC(msg->bid);
		fprintf(fdout, ",\"ack\":");
		if(msg->ack==0x15) {
			fprintf(fdout, "false");
		} else {
			PRINTC(msg->ack);
		}
		fprintf(fdout, ",\"tail\":");
		PRINTS(msg->addr);
	}
	fprintf(fdout, ",\"text\":");
	PRINTS(msg->txt);
	if (msg->be == 0x17)
		fprintf(fdout, ",\"end\":true");
	fprintf(fdout,"}\n");
	fflush(fdout);
}

#undef PRINTC
#undef PRINTS

static void printoneline(acarsmsg_t * msg, int chn, time_t t)
{
	char txt[30];
	char *pstr;

	strncpy(txt, msg->txt, 29);
	txt[29] = 0;
	for (pstr = txt; *pstr != 0; pstr++)
		if (*pstr == '\n' || *pstr == '\r')
			*pstr = ' ';

	fprintf(fdout, "#%1d (L:%4d E:%1d) ", chn + 1, msg->lvl, msg->err);

	if (inmode != 2)
		printdate(t);
	fprintf(fdout, " %7s %1c %2s ", msg->addr, msg->mode, msg->label);
	fprintf(fdout, "%s", txt);
	fprintf(fdout, "\n");
	fflush(fdout);
}


void outputmsg(const msgblk_t * blk)
{
	acarsmsg_t msg;
	int i, k;

	if (sockfd > 0) {
		if (netout == 1)
			outraw(blk, blk->chn, blk->tm);
	}

	/* fill msg struct */
	msg.lvl = blk->lvl;
	msg.err = blk->err;

	k = 0;
	msg.mode = blk->txt[k];
	k++;

	for (i = 0; i < 7; i++, k++) {
		msg.addr[i] = blk->txt[k];
	}
	msg.addr[7] = '\0';

	/* ACK/NAK */
	msg.ack = blk->txt[k];
	k++;

	msg.label[0] = blk->txt[k];
	k++;
	msg.label[1] = blk->txt[k];
	if(msg.label[1]==0x7f) msg.label[1]='d';
	k++;
	msg.label[2] = '\0';

	msg.bid = blk->txt[k];
	k++;

	/* txt start  */
	msg.bs = blk->txt[k];
	k++;

	msg.txt[0] = '\0';

	if ((msg.bs == 0x03 || msg.mode > 'Z') && airflt)
		return;

	if (msg.bs != 0x03) {
		/* Message txt */
		for (i = 0; k < blk->len - 1; i++, k++)
			msg.txt[i] = blk->txt[k];
		msg.txt[i] = 0;
	}

	/* txt end */
	msg.be = blk->txt[blk->len - 1];

	if (sockfd > 0) {
		if (netout == 0)
			outpp(&msg);
	}

	switch (outtype) {
	case 0:
		break;
	case 1:
		printoneline(&msg, blk->chn, blk->tm);
		break;
	case 2:
		printmsg(&msg, blk->chn, blk->tm);
		break;
	case 4:
		printjson(&msg, blk->chn, blk->tm);
		break;
	}
}
