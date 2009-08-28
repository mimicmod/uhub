/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2009, Jan Vidar Krey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "adcclient.h"

#define ADC_HANDSHAKE "HSUP ADBASE ADTIGR\n"
#define ADC_CID_SIZE 39

#define BIG_BUFSIZE 32768
#define TIGERSIZE 24


static void ADC_client_debug(struct ADC_client* client, const char* format, ...)
{
	char logmsg[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(logmsg, 1024, format, args);
	va_end(args);
	fprintf(stdout, "* [%p] %s\n", client, logmsg);
}

static void ADC_client_set_state(struct ADC_client* client, enum ADC_client_state state)
{
	client->state = state;
}

static ssize_t ADC_client_recv(struct ADC_client* client);
static void ADC_client_send_info(struct ADC_client* client);
static void ADC_client_on_connected(struct ADC_client* client);
static void ADC_client_on_disconnected(struct ADC_client* client);
static void ADC_client_on_login(struct ADC_client* client);
static int ADC_client_parse_address(struct ADC_client* client, const char* arg);

static void adc_cid_pid(struct ADC_client* client)
{
	char seed[64];
	char pid[64];
	char cid[64];
	uint64_t tiger_res1[3];
	uint64_t tiger_res2[3];

	/* create cid+pid pair */
	memset(seed, 0, 64);
	snprintf(seed, 64, VERSION "%p", client);
	
	tiger((uint64_t*) seed, strlen(seed), tiger_res1);
	base32_encode((unsigned char*) tiger_res1, TIGERSIZE, pid);
	tiger((uint64_t*) tiger_res1, TIGERSIZE, tiger_res2);
	base32_encode((unsigned char*) tiger_res2, TIGERSIZE, cid);
	
	cid[ADC_CID_SIZE] = 0;
	pid[ADC_CID_SIZE] = 0;
	
	strcat(client->info, " PD");
	strcat(client->info, pid);
	strcat(client->info, " ID");
	strcat(client->info, cid);
}


static void timer_callback(struct net_timer* t, void* arg)
{

}

static void event_callback(struct net_connection* con, int events, void *arg)
{
	struct ADC_client* client = (struct ADC_client*) arg;
	if (events == NET_EVENT_SOCKERROR || events == NET_EVENT_CLOSED)
	{
		client->callbacks.connection(client, -1, "Closed/socket error");
		return;
	}

	if (events == NET_EVENT_TIMEOUT)
	{
		if (client->state == ps_conn)
		{
			client->callbacks.connection(client, -2, "Connection timed out");
		}
	}

	if (events & NET_EVENT_READ)
	{
		if (ADC_client_recv(client) == -1)
		{
			ADC_client_on_disconnected(client);
		}
	}

	if (events & NET_EVENT_WRITE)
	{
		if (client->state == ps_conn)
		{
			ADC_client_connect(client, 0);
		}
		else
		{
			/* FIXME: Call send again */
		}
	}
}

static ssize_t ADC_client_recv(struct ADC_client* client)
{
	ssize_t size = net_con_recv(client->con, &client->recvbuf[client->r_offset], ADC_BUFSIZE - client->r_offset);
	if (size <= 0)
		return size;

	client->recvbuf[client->r_offset + size] = 0;

	char* start = client->recvbuf;
	char* pos;
	char* lastPos = 0;
	while ((pos = strchr(start, '\n')))
	{
		lastPos = pos;
		pos[0] = 0;

		ADC_client_debug(client, "- RECV: '%s'", start);

		fourcc_t cmd = 0;
		if (strlen(start) < 4)
		{
			ADC_client_debug(client, "Unexpected response from hub: '%s'", start);
			start = &pos[1];
			continue;
		}

		cmd = FOURCC(start[0], start[1], start[2], start[3]);
		switch (cmd)
		{
			case ADC_CMD_ISUP:
				break;

			case ADC_CMD_ISID:
				if (client->state == ps_protocol)
				{
					client->sid = string_to_sid(&start[5]);
					ADC_client_set_state(client, ps_identify);
					ADC_client_send_info(client);
				}
				break;

			case ADC_CMD_IINF:
				break;

			case ADC_CMD_BSCH:
			case ADC_CMD_FSCH:
			{
				break;
			}

			case ADC_CMD_BINF:
			{
				if (strlen(start) > 9)
				{
					char t = start[9]; start[9] = 0; sid_t sid = string_to_sid(&start[5]); start[9] = t;
					
					if (sid == client->sid)
					{
						if (client->state == ps_verify || client->state == ps_identify)
						{
							ADC_client_on_login(client);
						}
					}
				}
				break;
			}

			case ADC_CMD_ISTA:
				if (strncmp(start, "ISTA 000", 8))
				{
					ADC_client_debug(client, "status: '%s'\n", (start + 9));
				}
				break;
				
			default:
				break;
		}

		start = &pos[1];
	}

	if (lastPos)
	{
		client->r_offset = strlen(lastPos);
		memmove(client->recvbuf, lastPos, strlen(lastPos));
		memset(&client->recvbuf[client->r_offset], 0, ADC_BUFSIZE-client->r_offset);
	}
	else
	{
		// client->r_offset = size;
	}
	return 0;
}


void ADC_client_send(struct ADC_client* client, char* msg)
{
	int ret = net_con_send(client->con, msg, strlen(msg));

#ifdef ADC_CLIENT_DEBUG_PROTO
	char* dump = strdup(msg);
	dump[strlen(msg) - 1] = 0;
	ADC_client_debug(client, "- SEND: '%s'", dump);
	free(dump);
#endif

	if (ret != strlen(msg))
	{
		if (ret == -1)
		{
			if (net_error() != EWOULDBLOCK)
				ADC_client_on_disconnected(client);
		}
		else
		{
			/* FIXME: Not all data sent! */
			printf("ret (%d) != msg->length (%d)\n", ret, (int) strlen(msg));
		}
	}
}

void ADC_client_send_info(struct ADC_client* client)
{
	client->info[0] = 0;
	strcat(client->info, "BINF ");
	strcat(client->info, sid_to_string(client->sid));
	strcat(client->info, " NI");
	strcat(client->info, client->nick); /* FIXME: no escaping */
	strcat(client->info, "_");
	strcat(client->info, uhub_itoa(client->sid));
	strcat(client->info, " VE" VERSION);
	if (client->desc)
	{
		strcat(client->info, " DE");
		strcat(client->info, client->desc); /* FIXME: no escaping */
		
	}
	strcat(client->info, " I40.0.0.0");
	strcat(client->info, " EMuhub@extatic.org");
	strcat(client->info, " SL3");
	strcat(client->info, " HN1");
	strcat(client->info, " HR1");
	strcat(client->info, " HO1");

	adc_cid_pid(client);
	strcat(client->info, "\n");
	ADC_client_send(client, client->info);
}

int ADC_client_create(struct ADC_client* client, const char* nickname, const char* description)
{
	memset(client, 0, sizeof(struct ADC_client));

	int sd = net_socket_create(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sd == -1) return -1;

	client->con = hub_malloc(sizeof(struct net_connection));
	client->timer = hub_malloc(sizeof(struct net_timer));
	net_con_initialize(client->con, sd, 0, event_callback, client, 0);
	net_timer_initialize(client->timer, timer_callback, client);
	ADC_client_set_state(client, ps_none);

	client->nick = hub_strdup(nickname);
	client->desc = hub_strdup(description);

	return 0;
}

void ADC_client_destroy(struct ADC_client* client)
{
	ADC_client_disconnect(client);
	net_timer_shutdown(client->timer);
	hub_free(client->nick);
	hub_free(client->desc);
	hub_free(client->hub_address);
}


int ADC_client_connect(struct ADC_client* client, const char* address)
{
	if (!client->hub_address)
	{
		if (!ADC_client_parse_address(client, address))
			return 0;
		client->hub_address = hub_strdup(address);
	}

	int ret = net_connect(client->con->sd, (struct sockaddr*) &client->addr, sizeof(struct sockaddr_in));
	if (ret == 0 || (ret == -1 && net_error() == EISCONN))
	{
		ADC_client_on_connected(client);
	}
	else if (ret == -1 && (net_error() == EALREADY || net_error() == EINPROGRESS || net_error() == EWOULDBLOCK || net_error() == EINTR))
	{
		if (client->state != ps_conn)
		{
			net_con_update(client->con, NET_EVENT_READ | NET_EVENT_WRITE);
			ADC_client_set_state(client, ps_conn);
			ADC_client_debug(client, "connecting...");
		}
	}
	else
	{
		ADC_client_on_disconnected(client);
		return 0;
	}
	return 1;
}

static void ADC_client_on_connected(struct ADC_client* client)
{
	net_con_update(client->con, NET_EVENT_READ);
	ADC_client_send(client, ADC_HANDSHAKE);
	ADC_client_set_state(client, ps_protocol);
	ADC_client_debug(client, "connected.");
}

static void ADC_client_on_disconnected(struct ADC_client* client)
{
	net_con_close(client->con);
	hub_free(client->con);
	client->con = 0;
	ADC_client_debug(client, "disconnected.");
	ADC_client_set_state(client, ps_none);
}

static void ADC_client_on_login(struct ADC_client* client)
{
	ADC_client_debug(client, "logged in.");
	ADC_client_set_state(client, ps_normal);
}

void ADC_client_disconnect(struct ADC_client* client)
{
	if (client->con->sd != -1)
	{
		net_con_close(client->con);
		ADC_client_debug(client, "disconnected.");
	}
}

static int ADC_client_parse_address(struct ADC_client* client, const char* arg)
{
	char* split;
	struct hostent* dns;
	struct in_addr* addr;

	if (!arg)
		return 0;

	/* Minimum length of a valid address */
	if (strlen(arg) < 9)
		return 0;

	/* Check for ADC or ADCS */
	if (strncmp(arg, "adc://", 6) != 0 && strncmp(arg, "adcs://", 7) != 0)
		return 0;

	/* Split hostname and port (if possible) */
	split = strrchr(arg+6, ':');
	if (split == 0 || strlen(split) < 2 || strlen(split) > 6)
		return 0;

	/* Ensure port number is valid */
	int port = strtol(split+1, NULL, 10);
	if (port <= 0 || port > 65535)
		return 0;

	split[0] = 0;

	/* Resolve IP address (FIXME: blocking call) */
	dns = gethostbyname(arg+6);
	if (dns)
	{
		addr = (struct in_addr*) dns->h_addr_list[0];
	}

	// Initialize the sockaddr struct.
	memset(&client->addr, 0, sizeof(client->addr));
	client->addr.sin_family = AF_INET;
	client->addr.sin_port   = htons(port);
	memcpy(&client->addr.sin_addr, &addr, sizeof(struct in_addr));
	return 1;
}
