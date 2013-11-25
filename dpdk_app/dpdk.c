#include "http_server.h"

int numa_on = 1;
int promiscuous_on = 0;
struct rte_eth_link link;
int nb_txd = RTE_TEST_TX_DESC_DEFAULT;
int nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
struct rte_mempool* pktmbuf_pool[NB_SOCKETS];
struct lcore_conf lcore_conf[NUM_LCORE];
struct rte_eth_conf port_conf = {
	.link_speed = 0,
	.link_duplex = 0,
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
			.rss_key = NULL, /* Receive Side Scaling uses a random hash*/
			.rss_hf = ETH_RSS_IPV4, /*Applies to all IPV4 packets */
		},
	},
	.txmode = {
		/* no members, future extension */
	},
	/* Interrupts + Flow Director not initialized - defaults to disable */
};
const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
};
const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0,
	.tx_rs_thresh = 0,
};
struct ether_addr ports_eth_addr;

err_t dpdk_device_init(struct netif* netif) {
	struct lcore_conf *qconf;
	lcoreid = rte_lcore_id();
	qconf = &lcore_conf[lcoreid-START_CORE];
	if (!qconf) {
		return ERR_MEM;
	}
	netif->state = qconf;
	netif->name[0] = 'd';
	netif->name[1] = 'k';
	netif->output = etharp_output; /*this might need to change since we statically coded the ip-ether addr pairing */
	netif->linkoutput = dpdk_output;
	netif->mtu = 1500;
	netif->hwaddr_len = 6;
	netif->flags = NETIF_FLAG_ETHERNET | NETIF_FLAG_BROADCAST | NETIF_FLAG_IGMP; /*Not enabling ETHARP on this, so might need to change netif->output */
	
	return ERR_OK
	
}
err_t dpdk_input(struct rte_mbuf* m, struct netif* netif) {
	
	struct pbuf *p;
	uint16_t len;
	struct eth_hdr *ethhdr;
	len = m->pkt.pkt_len;
	p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);

	if (p != NULL) {
		/*assuming 2048 bytes is enough for independent data packets*/
		/*chaining not supported yet*/
		p->payload = m->pkt.data;	
	}	
	else {
		pbuf_free(p); /*memp uses an array with varying size interval inside the array to allocate memory (this array is in heap), seems to just reset the index so that the array can be written over*/
		rte_pktmbuf_free(m);  
		printf("Packet Dropped\n");	
	}
	ethhdr = (struct eth_hdr *)p->payload;
	/* add etharp_output cache entries for each ip address seen here so later when sending
	 * the reply, it doesn't have to do etharp_query and we don't have to keep track of
	 * which MAC address is which IP address here - need to change the timer on the etharp         * cache entries so they don't expire, just for now while this is still pretty hacked 	 */
	switch(htons(ethhdr->type)) {
	case ETHTYPE_IP:
	case ETHTYPE_ARP:
		//send up the stack, need to check if this frees p if successful
		if(ethernet_input(p, netif) != ERR_OK) {
			pbuf_free(p);
			p = NULL;
		} 
		break;
	default:
		pbuf_free(p)
		break;	
	}	
	/* In this implementation, each packet is processed completely before next one is grabbed, this could be problematic, however this way, we don't have to know when LWIP has finished with the packet and makes rte_pktmbuf_free simpler*/		
	/* Alternatively, we'll have to incorporate rte_pktmbuf_free(m) into LWIP, or run a clean up thread that clears out rte_pktmbuf once its refcnt goes to 0*/
	rte_pktmbuf_free(m);
}

err_t dpdk_output(struct netif *netif, struct pbuf *p) {
	struct rte_mbuf* m;
	
}

void send_burst(struct lcore_conf* qconf, uint16_t len, uint8_t port) {
	struct rte_mbuf **m_table;
	int ret;

	m_table = (struct rte_mbuf **) qconf->tx_mbufs.m_table; 
	ret = rte_eth_tx_burst(port, qconf->tx_queue_id, m_table, len);
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);

	}
}

__attribute__((noreturn)) int dpdk_driver(__attribute__((unused)) void *dummy) {
	unsigned lcoreid;
	struct lcore_conf *qconf;
	int nb_rx, j;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct netif* netif;
	
	lcoreid = rte_lcore_id();
	qconf = &lcore_conf[lcoreid-START_CORE];

	/* Set up LWIP for each core 
 	 * tcpip_init for LWIP was changed to not use mailboxes
 	 * currently just calls functions to initiate lwip, and */	
	netif = tcpip_init(tcpip_init_done, NULL); 

	while (1) {
		/* Transmit
                 * Commented out for now, because we finish everything in a loop so transmit
                 * happens whenever the higher layer calls it
                 * if batching is required later...then we'll have to figure a way for LWIP 
                 * and DPDK to do free() properly together */
		/*
		if(qconf->tx_mbufs.len != 0) {
			send_burst(qconf, qconf->tx_mbufs.len, 0);
			qconf->tx_mbufs.len = 0;
		}
		*/
		/* Receive */
		nb_rx = rte_eth_rx_burst(0, qconf->rx_queue_id, pkts_burst, MAX_PKT_BURST);
		for (j=0; j < nb_rx; j++) {
			dpdk_input(pkts_burst[j], netif); 
		}
	}		

}

int init_mem(void) {
	int lcoreid = 0;
	char s[64];
	int socketid;

	for (lcoreid = START_CORE; lcoreid < NUM_LCORE+START_CORE; lcoreid++) {
		if (rte_lcore_is_enabled(lcoreid) == 0)
			rte_exit(EXIT_FAILURE, "Wrong lcore mask\n");
		if (numa_on)
			socketid = rte_lcore_to_socket_id(lcoreid);
		else 
			socketid = 0;
		if (pktmbuf_pool[socketid] == NULL) {
			rte_snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
			pktmbuf_pool[socketid] = rte_mempool_create(s, NB_MBUF, MBUF_SIZE, 32, sizeof(struct rte_pktmbuf_pool_private), rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL, socketid, 0);
			if(pktmbuf_pool[socketid] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket%d\n", socketid);
			else 
				printf("Allocated mbuf pool on socket%d\n", socketid);
		
		}

	}
	return 0;

}

int lcore_setup(void) {
	int lcoreid=0;
	for (lcoreid = START_CORE; lcoreid < NUM_LCORE+START_CORE; lcoreid++) {
		lcore_conf[lcoreid - START_CORE].n_rx_queue = NUM_RX_QUEUES_PER_LCORE;
		lcore_conf[lcoreid - START_CORE].rx_queue_id = lcoreid-START_CORE;
		lcore_conf[lcoreid - START_CORE].tx_queue_id = lcoreid-START_CORE;	
		lcore_conf[lcoreid - START_CORE].rx_port_id = 0;
		lcore_conf[lcoreid - START_CORE].tx_port_id = 0;
	}	
	return 0;
}

int init_dpdk(int argc, char** argv) {
	int ret;
	int read;
	int lcoreid;
	uint16_t nb_rx_queue, nb_tx_queue;
	uint8_t socketid;
	ret = rte_eal_init(argc, argv);
	read = ret;
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	}
	ret = lcore_setup();
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error in setting up per lcore config\n");
	}	
	ret = init_mem();
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error in initializing memory\n");
	}
	ret = rte_ixgbe_pmd_init();
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Cannot attach to ixgbe pmd\n");
	}
	ret = rte_eal_pci_probe();
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Cannot attach to pci\n");
	}
	
	if (rte_eth_dev_count() != 1) {
		rte_exit(EXIT_FAILURE, "This program only works with one port\n");
	}
	if (rte_lcore_count() != NUM_LCORE) {
		rte_exit(EXIT_FAILURE, "This program only works with %d lcores\n", NUM_LCORE);
	}

	/* Initialize port */
	printf("Initializing port 0\n");
	fflush(stdout);
	nb_rx_queue = nb_tx_queue = NUM_LCORE;
        printf("Creating queues: nb_rxq:%hu, nb_txq:%hu ...\n", nb_rx_queue, nb_tx_queue);
	ret = rte_eth_dev_configure(0, nb_rx_queue, nb_tx_queue, &port_conf);
	if (ret < 0) 
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=0\n", ret);
	rte_eth_macaddr_get(0, &ports_eth_addr);	
	/*Set up transmit queues */
	for (lcoreid = START_CORE; lcoreid < NUM_LCORE+START_CORE; lcoreid++) {
		if(numa_on)
			socketid = (uint8_t) rte_lcore_to_socket_id(lcoreid);
		else 
			socketid = 0;
		ret = rte_eth_tx_queue_setup(0, lcore_conf[lcoreid-START_CORE].tx_queue_id, nb_txd, socketid, &tx_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err = %d, port=0\n", ret);
	}
  	for (lcoreid = START_CORE; lcoreid < NUM_LCORE+START_CORE; lcoreid++) {
		if (numa_on)
			socketid = (uint8_t) rte_lcore_to_socket_id(lcoreid);
		else
			socketid = 0;
		ret = rte_eth_rx_queue_setup(0, lcore_conf[lcoreid-START_CORE].rx_queue_id, nb_rxd, socketid, &rx_conf, pktmbuf_pool[socketid]);
		if (ret < 0) 
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err = %d, port = 0\n", ret);
	}
	/* start port */
	ret = rte_eth_dev_start(0);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_starts: err=%d, port=0\n", ret);
	rte_eth_link_get(0, &link);
	if (link.link_status) {
		printf(" Link Up - speed %u Mbps - %s\n", (unsigned) link.link_speed, (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex"):("half-duplex"));
	}
	else {
		printf(" Link Down\n");
	}
	if (promiscuous_on)
		rte_eth_promiscuous_enable(0);
	
	return read;
}
