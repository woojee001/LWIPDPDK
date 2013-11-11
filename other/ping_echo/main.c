#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>


#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>

#include "main.h"

#define RX_PTHRESH 8
#define RX_HTHRESH 8
#define RX_WTHRESH 4

#define TX_PTHRESH 36
#define TX_HTHRESH 0
#define TX_WTHRESH 0

#define START_CORE 0 
#define NUM_LCORE 8 
#define NUM_PORTS 1
#define NUM_TX_QUEUES_PER_LCORE NUM_PORTS
#define NUM_RX_QUEUES_PER_LCORE 1
#define NB_SOCKETS 2

#define NB_MBUF 8192
#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN 20000ULL /*around 100us at 2 Ghz */

#define DO_RFC_1812_CHECKS
#define RTE_LOGTYPE_PING_ECHO RTE_LOGTYPE_USER1
/* Configurable number of RX/TX ring descriptors */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* NUMA enable - socket 0 and socket 1 */
static int numa_on = 1;
/* Port promiscuous mode */
static int promiscuous_on = 0; 
/* mask of enabled ports - only have one Intel NIC, so enable port 0 */
static uint32_t enabled_port_mask = 1;
/* icmp header */
struct icmp_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	union {
		struct {
			uint16_t id;
			uint16_t sequence;
		} echo;
		uint32_t gateway;
		struct {
			uint16_t __unused;
			uint16_t mtu;
		} frag;
	}un;
} __attribute__ ((__packed__));
/* lcore paraemters */
struct lcore_params {
	uint8_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

//static struct lcore_params lcore_params_array[NUM_LCORE];
//static int nb_lcore_params = NUM_LCORE;
/* lcore rx queue information */
struct lcore_rx_queue {
	uint8_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;
/* mbuf table */ 
struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};
/* lcore configuration structure - RX and TX queues */
struct lcore_conf{
        uint16_t n_rx_queue;	
	struct lcore_rx_queue rx_queue_id ; 
	uint16_t tx_queue_id;
	struct mbuf_table tx_mbufs;
} __rte_cache_aligned;	
/* One core for receive, one core for transmit */
static struct lcore_conf lcore_conf[NUM_LCORE];

/* Memory Pool Structure allocated from hugepages for storing packets
 * - Better to allocate bunch of memory together instead of rte_malloc each 
 *   packet, kind of like mem_cache in linux where the memory is preallocated
 *   and used when a packet comes in, and free means it is reassigned as free 
 *   rather than actually freed (here it uses a ring struct called rte_ring)
 */
static struct rte_mempool * pktmbuf_pool[NB_SOCKETS]; 

/* Ethernet port configuration information */

static struct rte_eth_conf port_conf = {
	.link_speed = 0, /*autonegotiation*/
	.link_duplex = 0, /*autonegotiation*/
	.rxmode = {
		.split_hdr_size = 0,
		.header_split = 0, 
		.hw_ip_checksum = 1,
		.hw_vlan_filter = 0,
		.jumbo_frame = 0,
		.hw_strip_crc = 0,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL, /* Receive Side Scaling uses a random hash */
			.rss_hf = ETH_RSS_IPV4,	/* Applies to IPV4 packets */
		},
	},
	.txmode = { /* no members, future extension */
	},
	/* Interrupt + Flow Director not initialized - defaults to disable */
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD Default */
	.tx_rs_thresh = 0, /* Use PMD Default */

};

/* Ethernet address of the port */
static struct ether_addr ports_eth_addr;
static struct ether_addr sender_eth_addr = {
	.addr_bytes = {0, 28, 192, 55, 87, 178},
};

static inline int send_burst(struct lcore_conf* qconf, uint16_t n, uint8_t port) {
	struct rte_mbuf **m_table;
	int ret;
	uint16_t queueid;
	queueid = qconf->tx_queue_id; 
	m_table = (struct rte_mbuf **) qconf->tx_mbufs.m_table;

	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}
	return 0;
	

}

static inline int send_single_packet(struct rte_mbuf *m, uint8_t port) {
	uint32_t lcore_id;
	uint16_t len;
	struct lcore_conf *qconf;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id-START_CORE];
	len = qconf->tx_mbufs.len;
	qconf->tx_mbufs.m_table[len] = m;
 	len++;
	
	if (unlikely(len == MAX_PKT_BURST)) {
		send_burst(qconf, MAX_PKT_BURST, port);
		len = 0;
	}
	qconf->tx_mbufs.len = len;
	return 0;
}
static int init_mem(void) {
	int socketid;
	unsigned lcore_id;
	char s[64];
	
	for (lcore_id = START_CORE; lcore_id < NUM_LCORE+START_CORE; lcore_id++) {
		/* check if lcore 0 and 1 are enabled */
		if (rte_lcore_is_enabled(lcore_id) == 0) 
			rte_exit(EXIT_FAILURE, "Wrong lcore mask\n");
		if (numa_on)
			socketid = rte_lcore_to_socket_id(lcore_id);
		else 
			socketid = 0;
		if (socketid  >= NB_SOCKETS) {
			rte_exit(EXIT_FAILURE, "TOO MANY CPU SOCKETS\n");
		}
		if (pktmbuf_pool[socketid] == NULL) {
			rte_snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
			pktmbuf_pool[socketid] = rte_mempool_create(s, NB_MBUF, MBUF_SIZE, 32, sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL, socketid, 0);
			if(pktmbuf_pool[socketid] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket%d\n", socketid);
			else 
				printf("Allocated mbuf pool on socket %d\n", socketid);				
		}
	}

	return 0;
}

static int lcore_setup(void) {
	int lcoreid;
	//uint8_t lcore;
	/* The first for loop only works when theres one port, one queue, per lcore
	for (lcoreid=0; lcoreid < nb_lcore_params; lcoreid++) {
		lcore_params_array[lcoreid].port_id = 0;
		lcore_params_array[lcoreid].queue_id = lcoreid ;
		lcore_params_array[lcoreid].lcore_id = lcoreid;
	}
	*/
	for (lcoreid=START_CORE; lcoreid < NUM_LCORE+START_CORE; lcoreid++) {
		//lcore = lcore_params_array[lcoreid].lcore_id;
		lcore_conf[lcoreid-START_CORE].n_rx_queue =  NUM_RX_QUEUES_PER_LCORE;
		lcore_conf[lcoreid-START_CORE].rx_queue_id.queue_id = lcoreid-START_CORE;
		lcore_conf[lcoreid-START_CORE].rx_queue_id.port_id = 0;
	}
	return 0;
}
#ifdef DO_RFC_1812_CHECKS
static inline int is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len) {
	if (link_len < sizeof(struct ipv4_hdr))
		return -1;
	if (((pkt->version_ihl) >> 4) != 4)
		return -3;
	if ((pkt->version_ihl & 0xf) < 5)
		return -4;
	if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct ipv4_hdr))
		return -5;
	return 0;
}
#endif 
static inline int compare_eth_addr(struct ether_addr *ea_one, struct ether_addr *ea_two) {
	int i;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		if (ea_one->addr_bytes[i] != ea_two->addr_bytes[i] ) 
			return 0;
	}
	return 1;

}
static void print_ethaddr(const char *name, const struct ether_addr *eth_addr) {
	printf("%s%02X:%02X:%02X:%02X:%02x:%02X", name, eth_addr->addr_bytes[0], eth_addr->addr_bytes[1], eth_addr->addr_bytes[2], eth_addr->addr_bytes[3], eth_addr->addr_bytes[4], eth_addr->addr_bytes[5]);

}
static inline void ping_echo_reply(struct rte_mbuf *m, uint8_t portid) {
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct icmp_hdr *icmp_hdr;
	uint8_t dst_port; //only ethernet port 0 is available
	uint32_t dest_ip_addr, src_ip_addr;
	//struct ether_addr dest_eth_addr, src_eth_addr;	

	dst_port = portid;
	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char*) + sizeof(struct ether_hdr));
	icmp_hdr = (struct icmp_hdr *)(rte_pktmbuf_mtod(m, unsigned char*) + sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr));

#ifdef DO_RFC_1812_CHECKS
	/* Check to make sure the packet is valid (RFC1812) */
	if (is_valid_ipv4_pkt(ipv4_hdr, m->pkt.pkt_len) < 0) {
		rte_pktmbuf_free(m);
		return;
	}
#endif 
	//check source address is 198.162.52.113 or 3332519025 in unsigned int
	//check mac is 00:1c:c0:37:57:b2
	//check if icmp packet ipv4_hdr->next_proto_id = 0x01
	//check if icmp packet is a ping request
	src_ip_addr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	dest_ip_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);

	//ether_addr_copy(&eth_hdr->s_addr, &src_eth_addr);
	//ether_addr_copy(&eth_hdr->d_addr, &dest_eth_addr);
	
	printf("Received packet SRC: %d.%d.%d.%d\n", (src_ip_addr>> 24) & 0xFF, (src_ip_addr >> 16) & 0xFF, (src_ip_addr >> 8) & 0xFF, src_ip_addr & 0xFF);
	printf("Received packet DST: %d.%d.%d.%d\n", (dest_ip_addr >> 24) & 0xFF, (dest_ip_addr >> 16) & 0xFF, (dest_ip_addr >> 8) & 0xFF, dest_ip_addr & 0xFF);

	//print_ethaddr(" SRC Address: ", &src_eth_addr);
	//print_ethaddr(" DST Address: ", &dest_eth_addr);

	//printf("\n");

	//printf(" Layer 4 packet type is : %d\n", ipv4_hdr->next_proto_id);
	

	if (src_ip_addr == 3332519025 && compare_eth_addr(&eth_hdr->s_addr, &sender_eth_addr) && compare_eth_addr(&eth_hdr->d_addr, &ports_eth_addr)) {
		if (ipv4_hdr->next_proto_id == 1 && icmp_hdr->type == 8) {
			//printf("received an ICMP packet from desired sender\n");			printf("constructing reply packet...\n");
			icmp_hdr->type = 0;
			icmp_hdr->checksum += 8; 
			ipv4_hdr->src_addr = rte_cpu_to_be_32(dest_ip_addr);
			ipv4_hdr->dst_addr = rte_cpu_to_be_32(src_ip_addr);
			ether_addr_copy(&ports_eth_addr, &eth_hdr->s_addr);
			ether_addr_copy(&sender_eth_addr, &eth_hdr->d_addr);
			
			send_single_packet(m, dst_port);
		}
		else {
			rte_pktmbuf_free(m);
			return;
		}			
	} 
	else {
		rte_pktmbuf_free(m);
		return;
	}
	//Construct new Ethernet header
	//Change dst mac to src mac
	//Change src mac to dst mac

	//Construct new IP header
	//Change src to dest
        //Change dst to src
	//change TTL
	//Recalculate checksum

	//Change ICMP header
	//Change Type from 8 to 0
	//Recalculate checksum
}

static __attribute__((noreturn)) int  main_loop(__attribute__((unused)) void *dummy) {
	
	//uint64_t prev_tsc = 0;
	//uint64_t diff_tsc, cur_tsc;
	int i,j, nb_rx;
	uint8_t portid, queueid;
	unsigned lcore_id;
	struct lcore_conf *qconf;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];	

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id-START_CORE];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, PING_ECHO, "lcore %u has nothing to do\n", lcore_id);
		while(1);
	}
	
	RTE_LOG(INFO, PING_ECHO, "entering main loop on lcore %u\n", lcore_id);

	for (i=0;i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_id.port_id;
		queueid = qconf->rx_queue_id.queue_id;
		RTE_LOG(INFO, PING_ECHO, " -- lcoreid=%u portid=%hhu rxqueueid =%hhu\n", lcore_id, portid, queueid);
	}
	
	while (1) {
		//cur_tsc = rte_rdtsc();
		//  Send packet from TX queue 
		//diff_tsc = cur_tsc - prev_tsc;
		//if (unlikely(diff_tsc > BURST_TX_DRAIN)) {
			for (portid = 0; portid < NUM_PORTS; portid++) {
				if (qconf->tx_mbufs.len == 0) 
					continue;
				send_burst(&lcore_conf[lcore_id-START_CORE], qconf->tx_mbufs.len, portid);
				qconf->tx_mbufs.len=0;
			}
		//	prev_tsc = cur_tsc;
		//}
		//  Read packet from RX queue 
		for (i = 0; i < qconf->n_rx_queue; i++) {
			portid = qconf->rx_queue_id.port_id;
			queueid = qconf->rx_queue_id.queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);
			for (j=0; j< nb_rx; j++) {
				ping_echo_reply(pkts_burst[j], portid);
			}
		}
	}
}	

int MAIN(int argc, char **argv) {

	int ret, lcore_id, queueid, queue;
	unsigned nb_ports, nb_lcores;
	uint16_t  nb_rx_queue, nb_tx_queue;
	uint8_t portid , socketid; 
	struct rte_eth_link link;
	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0) 
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = lcore_setup();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid packet_reply parameters\n");

	ret = init_mem();
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "init_mem failed\n"); 
	}
#ifdef RTE_LIBRTE_IGB_PMD
	if (rte_igb_pmd_init() < 0) 
		rte_exit(EXIT_FAILURE, "Cannot init igb pmd\n");
#endif
#ifdef RTE_LIBRTE_IXGBE_PMD
	if (rte_ixgbe_pmd_init() < 0)
		rte_exit(EXIT_FAILURE, "Cannot init ixgbe pmd\n");
#endif
	if (rte_eal_pci_probe() < 0)
		rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");
	
	nb_ports = rte_eth_dev_count();
        if (nb_ports != 1)
		rte_exit(EXIT_FAILURE, "This program only works with 1 port\n");
        nb_lcores = rte_lcore_count();
	if (nb_lcores != NUM_LCORE)
		rte_exit(EXIT_FAILURE, "This program only works with %d  lcores\n", nb_lcores);
	
	/* Initialize all ports - only loops once */
	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid))==0) {
			rte_exit(EXIT_FAILURE, "PORT 0 NOT ENABLED\n");
		}
		
		printf("Initializing port %d ... ", portid); 
		fflush(stdout);

		nb_rx_queue = nb_lcores; //nb_lcores rx queues on port 0 for the two lcores
		nb_tx_queue = nb_lcores; //nb_lcores tx queues on port 0 for the two lcores  
		printf("Creating queues: nb_rxq=%hu nb_txq=%hu... ", nb_rx_queue, nb_tx_queue);
		ret = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &port_conf); 
		if (ret < 0) 
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", ret, portid); 
		rte_eth_macaddr_get(portid, &ports_eth_addr); /*if theres more ports, ports_eth_addr needs to be an array*/
		print_ethaddr(" Address:", &ports_eth_addr);
		printf(", ");

		/* init one TX queue per (lcore, port) couple */
		queueid = 0;
		for (lcore_id = START_CORE; lcore_id < NUM_LCORE+START_CORE; lcore_id++) {
			if (rte_lcore_is_enabled(lcore_id)==0)
				rte_exit(EXIT_FAILURE, "lcore %d-%d initialized\n",START_CORE, NUM_LCORE+START_CORE-1);
			if(numa_on)
				socketid = (uint8_t) rte_lcore_to_socket_id(lcore_id);
			else
				socketid = 0;
			printf("txq=%d, %d, %u ", lcore_id, queueid, socketid);
			fflush(stdout);
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd, socketid, &tx_conf);
			if (ret < 0) 
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup err=%d, port=%d\n", ret, portid);
		
			lcore_conf[lcore_id-START_CORE].tx_queue_id = queueid; 
			queueid++;
		}
		printf("\n");
	}
	for (lcore_id = START_CORE; lcore_id < NUM_LCORE+START_CORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			rte_exit(EXIT_FAILURE, "lcore %d-%d not enabled\n",START_CORE, NUM_LCORE+START_CORE-1);
		printf("\n Initializing rx queues on lcore %d ... ", lcore_id);
		fflush(stdout);

		/* init RX queues */
		for (queue=0; queue < lcore_conf[lcore_id-START_CORE].n_rx_queue; queue++) {
			portid = lcore_conf[lcore_id-START_CORE].rx_queue_id.port_id;
			queueid = lcore_conf[lcore_id-START_CORE].rx_queue_id.queue_id;

			if (numa_on)
				socketid = (uint8_t) rte_lcore_to_socket_id(lcore_id);
			else 
				socketid = 0;
			printf("rxq = %d, %d, %d ", portid, queueid, socketid);
			fflush(stdout);
			
			ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid, &rx_conf, pktmbuf_pool[socketid]);
			if (ret< 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err = %d, port=%d\n", ret, portid);
		}
	}	
	printf("\n");
	/* start ports */
	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0) 
			rte_exit(EXIT_FAILURE, "Ethernet Device not enabled\n");
		ret=rte_eth_dev_start(portid);
	 	if (ret < 0) 
			rte_exit(EXIT_FAILURE, "rte_eth_dev_starts: err=%d, port=%d\n", ret, portid);
		printf("done: Port %d ", portid);

		/* get link status */
		rte_eth_link_get(portid, &link);
		if (link.link_status) {
			printf(" Link Up - speed %u Mbps - %s\n", (unsigned) link.link_speed, (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duples"):("half-duplex\n"));
		}	
		else {
			printf(" Link Down\n");
		}
		if (promiscuous_on)
			rte_eth_promiscuous_enable(portid);
	}
	
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id)<0)
			return -1;
	}
	return 0;	
}	
