/*
 * snull.c --  the Simple Network Utility
 *
 * Copyright (C) 2001 Alessandro Rubini and Jonathan Corbet
 * Copyright (C) 2001 O'Reilly & Associates
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  The citation
 * should list that the code comes from the book "Linux Device
 * Drivers" by Alessandro Rubini and Jonathan Corbet, published
 * by O'Reilly & Associates.   No warranty is attached;
 * we cannot take responsibility for errors or fitness for use.
 *
 * $Id: snull.c,v 1.21 2004/11/05 02:36:03 rubini Exp $
 */


#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

#include <linux/sched.h>
#include <linux/kernel.h> /* printk() */
#include <linux/slab.h> /* kmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */

#include <linux/in.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/tcp.h>         /* struct tcphdr */
#include <linux/skbuff.h>

#include "snull.h"

#include <linux/my_spinlock_k.h>
#include <linux/in6.h>
#include <asm/checksum.h>
#include <asm/apic.h>        /*  */
#include <asm/apicdef.h>
#include <asm-generic/percpu.h>
#include <linux/signal.h>
#include <linux/smp.h>
#include <linux/getcpu.h>
#include <asm/desc.h>
#include <asm/desc_defs.h>
#include <asm/irq.h>
#include <asm/hw_irq.h>      /* define vector_irq */
#include <linux/irqreturn.h>
#include <linux/interrupt.h> /* mark_bn, request_irq, 
                                flags used only by the kernel as 
                                part of the irq handling routines */
#include <linux/semaphore.h>


#define MINT_SHARED_MEM_START 0x1001000
#define CPU_CF 2808.731
#define MAX_MTU 1500
#define MAX_ETHER_PACKET_LEN 1528
#define BUF_ENTRY_NUM 512
#define BUF_ENTRY_NUM_H 256
#define MAX_QUEUE_NUM 64
#define IPI_REQ 16

MODULE_AUTHOR("Alessandro Rubini, Jonathan Corbet");
MODULE_LICENSE("Dual BSD/GPL");

struct buf_t {
    int len;
    char packet[MAX_ETHER_PACKET_LEN];
};

struct packs_queue {
    int head;
    int tail;
    struct buf_t buf[BUF_ENTRY_NUM_H];
};

struct shared_mem {
    int lock;
    struct packs_queue queue[2];
};
/*
struct addr_manager{
    int head;
    int tail;
    long list[BUF_ENTRY_NUM_H];
};

struct shared_mem {
    int buf_controller[BUF_ENTRY_NUM];
    struct addr_manager amanager[2];
    struct buf_t buf[BUF_ENTRY_NUM];
};
*/
volatile int nested_interrupt_check = 0, nested_interrupt_count = 0;

struct shared_mem *shmem = (struct shared_mem *)__va(MINT_SHARED_MEM_START);
struct packs_queue *tx_queue, *rx_queue;
/*
 * Transmitter lockup simulation, normally disabled.
 */
static int lockup = 0;
module_param(lockup, int, 0);

static int timeout = SNULL_TIMEOUT;
module_param(timeout, int, 0);


/*
 * Do we run in NAPI mode?
 */
static int use_napi = 1;
module_param(use_napi, int, 0);


struct net_device *snull_devs[2];

int pool_size = 8;
module_param(pool_size, int, 0);

/*
 * This structure is private to each device. It is used to pass
 * packets in and out, so there is place for a packet
 */

struct snull_priv {
	struct net_device_stats stats;
	int status;
	int rx_int_enabled;
	int tx_packetlen;
	u8 *tx_packetdata;
	struct sk_buff *skb;
	spinlock_t lock;
	struct net_device *dev;
	struct napi_struct napi;
};

static void snull_tx_timeout(struct net_device *dev);

//static void (*snull_interrupt)(int, void *, struct pt_regs *);
static irqreturn_t snull_napi_interrupt(int irq, void *dev_id);
//static irqreturn_t snull_regular_interrupt(int irq, void *dev_id);


/*
 * Enable and disable receive interrupts.
 */
static void snull_rx_ints(struct net_device *dev, int enable)
{
	struct snull_priv *priv = netdev_priv(dev);
	priv->rx_int_enabled = enable;
}


struct packs_queue * queue_init(struct packs_queue * queue){
    queue->head = 0;
    queue->tail = 0;
    return queue;
}

/*
 * Open and close
 */
int snull_open(struct net_device *dev)
{
    int retval, irq = IPI_REQ;
    char *name = "snull";
    nested_interrupt_check = 0;
    nested_interrupt_count = 0;
    printk("check: %d count: %d\n", nested_interrupt_check, nested_interrupt_count);
    printk("snull tx_rx_buf size: %lu\n",sizeof(struct shared_mem));
    printk("snull struct packs_queue size: %lu\n",sizeof(struct packs_queue));
    /* request_region(), request_irq(), ....  (like fops->open) */

    retval = request_irq(irq, snull_napi_interrupt, IRQF_DISABLED, name, dev);
    //retval = request_irq(irq, snull_regular_interrupt, IRQF_DISABLED, name, dev);
    
    per_cpu(vector_irq, 0)[100] = irq;
    /*
     * Assign the hardware address of the board: use "\0SNULx", where
     * x is 0 or 1. The first byte is '\0' to avoid being a multicast
     * address (the first byte of multicast addrs is odd).
     */
    memcpy(dev->dev_addr, "\0SNUL0", ETH_ALEN);
    if(dev == snull_devs[0])
    {
        printk("I am snull[0].\n");
        shmem->lock = 0;
        tx_queue = queue_init(&(shmem->queue[1]));
        rx_queue = queue_init(&(shmem->queue[0]));
        my_spinlock_init(1);
        //snull_unlock(&(shmem->lock));
    }
    if(dev == snull_devs[1])
    {
        printk("I am snull[1].\n");
        tx_queue = &(shmem->queue[0]);
        rx_queue = &(shmem->queue[1]);
        dev->dev_addr[ETH_ALEN-1]++; /* \0SNUL1 */
    }

    netif_start_queue(dev);
    return 0;
}

/*
 * Dump shared_mem
 */
 /*
int dump_shared_mem(void){
    int i,j;
    printk("--------------------- < DUMP START > ---------------------\n");
    printk("lock: %d\n", shmem->lock);
    for(i = 0; i < 2; i++)
    {
        printk("queue%d:\n", i);
        printk("    head: %d\n", shmem->queue[i].head);
        printk("    tail: %d\n", shmem->queue[i].tail); 
        printk("    position:");
        for(j = 0; j < MAX_QUEUE_NUM; j++)
        {
            if((j % 10) == 0)printk("\n                    ");
            printk(" %4d",shmem->queue[i].position[j]);
        }
        printk("\n");
    }
    printk("buf_manager:\n");
        for(j = 0; j < BUF_ENTRY_NUM; j++ )
        {
            if((j % 20) == 0)printk("\n                  ");
            printk(" %d",shmem->buf_manager[j]);
        }
        printk("\n");
    printk("--------------------- <    END    > ---------------------\n");
    return 1;
}
*/

int snull_release(struct net_device *dev)
{
    /* release ports, irq and such -- like fops->close */
    int irq = IPI_REQ;
    struct snull_priv *priv = netdev_priv(dev);
    napi_disable(&priv->napi);
    netif_stop_queue(dev); /* can't transmit any more */
    free_irq(irq, dev);
    printk("check: %d count: %d\n", nested_interrupt_check, nested_interrupt_count);
    return 0;
}

/*
 * Configuration changes (passed on by ifconfig)
 */
int snull_config(struct net_device *dev, struct ifmap *map)
{
    if (dev->flags & IFF_UP) /* can't act on a running interface */
        return -EBUSY;

    /* Don't allow changing the I/O address */
    if (map->base_addr != dev->base_addr) {
        printk(KERN_WARNING "snull: Can't change I/O address\n");
        return -EOPNOTSUPP;
    }

    /* Allow changing the IRQ */
    if (map->irq != dev->irq) {
        dev->irq = map->irq;
        /* request_irq() is delayed to open-time */
    }

    /* ignore other fields */
    return 0;
}


static int snull_poll(struct napi_struct *napi, int budget)
{
    struct sk_buff *skb;
    struct snull_priv *priv = container_of(napi, struct snull_priv, napi);
    struct net_device *dev = priv->dev;
    int len, work_done = 0;
    void *addr;
    if((rx_queue->head == rx_queue->tail)){
            napi_complete(napi);
            goto out;
    }
    for(work_done = 0; work_done < budget; work_done++){
        len = rx_queue->buf[rx_queue->head].len;
        skb = dev_alloc_skb(len + 2);
        if (!skb) {
            if (printk_ratelimit())
                printk(KERN_NOTICE "snull rx: low on mem - packet dropped\n");
            priv->stats.rx_dropped++;
            work_done--;
            continue;
        }

        skb_reserve(skb, 2); /* align IP on 16B boundary */
        my_spin_lock();
        addr = (void *)rx_queue->buf[rx_queue->head].packet;
        memcpy(skb_put(skb, len), addr, len);
        (rx_queue->head) = ((rx_queue->head) + 1) % 256;
        /* If we processed all packets, we're done; tell the kernel and reenable ints */
        my_spin_unlock();
        skb->dev = dev;
        skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
        skb->protocol = eth_type_trans(skb, dev);
        netif_receive_skb(skb);
        
        /* Maintain stats */
        priv->stats.rx_packets++;
        priv->stats.rx_bytes += len;
        if((rx_queue->head == rx_queue->tail))
        {
            napi_complete(napi);
            break;
        }
    }

out:
    /* if a packet txed in this area, it is left in the buf */
    snull_rx_ints(dev, 1);
    return work_done;
}   


void snull_rx(struct net_device *dev, struct snull_packet *pkt){
    struct sk_buff *skb;
    struct snull_priv *priv = netdev_priv(dev);
    int len, work_done = 0;
    int budget = 32;
    void *addr;
    if((rx_queue->head == rx_queue->tail)){
            goto out;
    }
    for(work_done = 0; work_done < budget; work_done++){
        len = rx_queue->buf[rx_queue->head].len;
        skb = dev_alloc_skb(len + 2);
        if (!skb) {
            if (printk_ratelimit())
                printk(KERN_NOTICE "snull rx: low on mem - packet dropped\n");
            priv->stats.rx_dropped++;
            work_done--;
            continue;
        }

        skb_reserve(skb, 2); /* align IP on 16B boundary */ 
        addr = (void *)rx_queue->buf[rx_queue->head].packet;
        memcpy(skb_put(skb, len), addr, len);
        (rx_queue->head) = ((rx_queue->head) + 1) % 256;
        /* If we processed all packets, we're done; tell the kernel and reenable ints */
        skb->dev = dev;
        skb->ip_summed = CHECKSUM_UNNECESSARY; /* don't check it */
        skb->protocol = eth_type_trans(skb, dev);
        netif_rx(skb);
        
        /* Maintain stats */
        priv->stats.rx_packets++;
        priv->stats.rx_bytes += len;
        if((rx_queue->head == rx_queue->tail))
        {
            break;
        }
    }

out:
    /* if a packet txed in this area, it is left in the buf */
    shmem->lock = 0;
}



static irqreturn_t snull_regular_interrupt(int irq, void *dev_id){
    struct snull_priv *priv;
    struct snull_packet *pkt = NULL;
    struct net_device *dev = (struct net_device *)dev_id;

    if(!dev)
        return;

    priv = netdev_priv(dev);
    
    if(shmem->lock == 0){
        shmem->lock = 1;  /* Disable further interrupts */
        snull_rx(dev, pkt);
    }

    return IRQ_HANDLED;
}


/*
 * A NAPI interrupt handler.
 */
static irqreturn_t snull_napi_interrupt(int irq, void *dev_id)
{
    int statusword;
    struct snull_priv *priv;
    if(nested_interrupt_check != 0)
        nested_interrupt_count++;
    nested_interrupt_check = 1;
    /*
     * As usual, check the "device" pointer for shared handlers.
     * Then assign "struct device *dev"
     */
    struct net_device *dev = (struct net_device *)dev_id;
    /* ... and check with hw if it's really ours */
    /* if(dev == snull_devs[0] || dev == snull_devs[1]){
       printk("recieved snull_dev\n");
       }else{
       printk("miss\n");
       }
     */
    /* paranoid */
    if (!dev)
        return IRQ_NONE;

    /* Lock the device */
    priv = netdev_priv(dev);

    /* retrieve statusword: real netdevices use I/O instructions */
    //statusword = priv->status;
    //priv->status = 0;
    //if (statusword & SNULL_RX_INTR) {
    if(priv->rx_int_enabled == 1){
        statusword = 1;
        snull_rx_ints(dev, 0);  /* Disable further interrupts */
        napi_schedule(&priv->napi);
    }
    //if (statusword & SNULL_TX_INTR) {
    /* a transmission is over: free the skb */
    //priv->stats.tx_packets++;
    //priv->stats.tx_bytes += priv->tx_packetlen;
    //dev_kfree_skb(priv->skb);
    //}

    /* Unlock the device and we are done */
    nested_interrupt_check = 0;
    return IRQ_RETVAL(statusword);
}



/*
 * Transmit a packet (low level interface)
 */

int snull_send_ipi(void){
    int phys_apicid;

    phys_apicid = per_cpu(x86_bios_cpu_apicid, 1);
    apic_icr_write(APIC_INT_ASSERT | APIC_DEST_PHYSICAL | APIC_DM_FIXED | 100, phys_apicid);
    apic_wait_icr_idle();
    return 1;
}

int snull_hw_tx(char *buf, int len, struct net_device *dev)
{
    //printk("hw_tx: enter");
    // This function deals with hw details. This interface loops
    // back the packet to the other snull interface (if any).
    // In other words, this function implements the snull behaviour,
    // while all other procedures are rather device-independent

    struct iphdr *ih;
    //struct net_device *dest;
    struct snull_priv *priv = netdev_priv(dev);
    u32 *saddr, *daddr;
    //struct snull_packet *tx_buffer;
    int i;
    //  unsigned int tsc_l1, tsc_l2, tsc_u1, tsc_u2;
    //  unsigned long int tsc1, tsc2;
    //  rdtsc_64(tsc_l1, tsc_u1);
    // I am paranoid. Ain't I? 
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        printk("snull: Hmm... packet too short (%i octets)\n",
                len);
        return -1;
    }

    if (0) { // enable this conditional to look at the data
        int i;
        PDEBUG("len is %i\n" KERN_DEBUG "data:",len);
        for (i=14 ; i<len; i++)
            printk(" %02x",buf[i]&0xff);
        printk("\n");
    }
    // Ethhdr is 14 bytes, but the kernel arranges for iphdr
    // to be aligned (i.e., ethhdr is unaligned)

    ih = (struct iphdr *)(buf+sizeof(struct ethhdr));
    saddr = &ih->saddr;
    daddr = &ih->daddr;

    ((u8 *)saddr)[2] ^= 1; // change the third octet (class C)
    ((u8 *)daddr)[2] ^= 1;

    ih->check = 0;         // and rebuild the checksum (ip needs it)
    ih->check = ip_fast_csum((unsigned char *)ih,ih->ihl);

    if (dev == snull_devs[0])
        PDEBUGG("%08x:%05i --> %08x:%05i\n",
                ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source),
                ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest));
    else
        PDEBUGG("%08x:%05i <-- %08x:%05i\n",
                ntohl(ih->daddr),ntohs(((struct tcphdr *)(ih+1))->dest),
                ntohl(ih->saddr),ntohs(((struct tcphdr *)(ih+1))->source));

    // Ok, now the packet is ready for transmission: first simulate a
    // receive interrupt on the twin device, then  a
    // transmission-done on the transmitting device

    int new_tail;
    new_tail = (((tx_queue->tail) + 1) % 256);
    if(new_tail == (tx_queue->head))
    {
        //printk("full stacked\n");
        snull_send_ipi();
        priv->stats.tx_dropped++;
        return -1;
    }else{
        my_spin_lock();
        tx_queue->buf[tx_queue->tail].len = len;
        //printk("[hw_tx] len: %d i: %d\n", len, i);
        memcpy((void *)tx_queue->buf[tx_queue->tail].packet, buf, len);
        (tx_queue->tail) = new_tail;
        my_spin_unlock();
        if(shmem->lock == 0){
            snull_send_ipi();
        }
        priv = netdev_priv(dev);
        if (lockup && ((priv->stats.tx_packets + 1) % lockup) == 0) {
            // Simulate a dropped transmit interrupt
            netif_stop_queue(dev);
            PDEBUG("Simulate lockup at %ld, txp %ld\n", jiffies,
                    (unsigned long) priv->stats.tx_packets);
        }
        else{
            priv->stats.tx_packets++;
            priv->stats.tx_bytes += len;
            dev_kfree_skb(priv->skb);
        }
    }

    //  rdtsc_64(tsc_l2, tsc_u2);
    //  tsc1=(unsigned long int)tsc_u1 << 32 | tsc_l1;
    //  tsc2=(unsigned long int)tsc_u2 << 32 | tsc_l2;
    //  printk("send: %ld\n", (tsc2-tsc1)/(CPU_CF));

    //    if (priv->rx_int_enabled) {
    //		priv->status |= SNULL_RX_INTR;
    //		snull_interrupt(0, dest, NULL);
    //	}

        return 0;

}


/*
 * Transmit a packet (called by the kernel)
 */
int snull_tx(struct sk_buff *skb, struct net_device *dev)
{
    int len, ret;
    //unsigned int *tx_lock;
    //int irq;
    char *data, shortpkt[ETH_ZLEN];
    struct snull_priv *priv = netdev_priv(dev);

    data = skb->data;
    len = skb->len;
    if (len < ETH_ZLEN) {
        memset(shortpkt, 0, ETH_ZLEN);
        memcpy(shortpkt, skb->data, skb->len);
        len = ETH_ZLEN;
        data = shortpkt;
    }
    if (len > MAX_ETHER_PACKET_LEN)
    {
        printk("tx packet len: too large\n");
        return -1;
    }
    dev->trans_start = jiffies; /* save the timestamp */

    /* Remember the skb, so we can free it at interrupt time */
    priv->skb = skb;
    
    /* actual deliver of data is device-specific, and not shown here */
    ret = snull_hw_tx(data, len, dev);
    return ret;
}

/*
 * Deal with a transmit timeout.
 */
void snull_tx_timeout (struct net_device *dev)
{
    struct snull_priv *priv = netdev_priv(dev);

    PDEBUG("Transmit timeout at %ld, latency %ld\n", jiffies,
            jiffies - dev->trans_start);
    /* Simulate a transmission interrupt to get things moving */
    priv->status = SNULL_TX_INTR;
    //snull_interrupt(0, dev, NULL);
    priv->stats.tx_errors++;
    netif_wake_queue(dev);
    return;
}



/*
 * Ioctl commands 
 */
int snull_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
    PDEBUG("ioctl\n");
    return 0;
}

/*
 * Return statistics to the caller
 */
struct net_device_stats *snull_stats(struct net_device *dev)
{
    struct snull_priv *priv = netdev_priv(dev);
    return &priv->stats;
    //dump_shared_mem();
}

/*
 * This function is called to fill up an eth header, since arp is not
 * available on the interface
 */
int snull_rebuild_header(struct sk_buff *skb)
{
    struct ethhdr *eth = (struct ethhdr *) skb->data;
    struct net_device *dev = skb->dev;

    memcpy(eth->h_source, dev->dev_addr, dev->addr_len);
    memcpy(eth->h_dest, dev->dev_addr, dev->addr_len);
    eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
    return 0;
}


int snull_header(struct sk_buff *skb, struct net_device *dev,
        unsigned short type, const void *daddr, const void *saddr,
        unsigned len)
{
    struct ethhdr *eth = (struct ethhdr *)skb_push(skb,ETH_HLEN);

    eth->h_proto = htons(type);
    memcpy(eth->h_source, saddr ? saddr : dev->dev_addr, dev->addr_len);
    memcpy(eth->h_dest,   daddr ? daddr : dev->dev_addr, dev->addr_len);
    eth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
    return (dev->hard_header_len);
}





/*
 * The "change_mtu" method is usually not needed.
 * If you need it, it must be like this.
 */
int snull_change_mtu(struct net_device *dev, int new_mtu)
{
    unsigned long flags;
    struct snull_priv *priv = netdev_priv(dev);
    spinlock_t *lock = &priv->lock;

    /* check ranges */
    if ((new_mtu < 68) || (new_mtu > 1500))
        return -EINVAL;
    /*
     * Do anything you need, and the accept the value
     */
    spin_lock_irqsave(lock, flags);
    dev->mtu = new_mtu;
    spin_unlock_irqrestore(lock, flags);
    return 0; /* success */
}

static const struct header_ops snull_header_ops = {
    .create  = snull_header,
    .rebuild = snull_rebuild_header
};

static const struct net_device_ops snull_netdev_ops = {
    .ndo_open            = snull_open,
    .ndo_stop            = snull_release,
    .ndo_start_xmit      = snull_tx,
    .ndo_do_ioctl        = snull_ioctl,
    .ndo_set_config      = snull_config,
    .ndo_get_stats       = snull_stats,
    .ndo_change_mtu      = snull_change_mtu,
    .ndo_tx_timeout      = snull_tx_timeout
};

/*
 * The init function (sometimes called probe).
 * It is invoked by register_netdev()
 */
void snull_init(struct net_device *dev)
{
    struct snull_priv *priv;
#if 0
    /*
     * Make the usual checks: check_region(), probe irq, ...  -ENODEV
     * should be returned if no device found.  No resource should be
     * grabbed: this is done on open(). 
     */
#endif

    /* 
     * Then, assign other fields in dev, using ether_setup() and some
     * hand assignments
     */
    ether_setup(dev); /* assign some of the fields */
    dev->mtu = MAX_MTU;
    dev->watchdog_timeo = timeout;
    dev->netdev_ops = &snull_netdev_ops;
    dev->header_ops = &snull_header_ops;
    /* keep the default flags, just add NOARP */
    dev->flags           |= IFF_NOARP;
    dev->features        |= NETIF_F_HW_CSUM;

    /*
     * Then, initialize the priv field. This encloses the statistics
     * and a few private fields.
     */
    //memset(priv, 0, sizeof(struct snull_priv));
    priv = netdev_priv(dev);
    printk("initialize snull_priv\n");
    netif_napi_add(dev, &priv->napi, snull_poll, 256);
    printk("finished netif_napi_add");
    priv->dev=dev;
    napi_enable(&priv->napi);
    printk("set up napi_struct\n");
    spin_lock_init(&priv->lock);
    snull_rx_ints(dev, 1);		/* enable receive interrupts */
    //snull_setup_pool(dev);
}

/*
 * The devices
 */




/*
 * Finally, the module stuff
 */

void snull_cleanup(void)
{
    int i;

    for (i = 0; i < 2;  i++) {
        if (snull_devs[i]) {
            unregister_netdev(snull_devs[i]);
            //snull_teardown_pool(snull_devs[i]);
            free_netdev(snull_devs[i]);
        }
    }
    return;
}



int snull_init_module(void)
{
    int result, i, ret = -ENOMEM;

    /* Allocate the devices */
    snull_devs[0] = alloc_netdev(sizeof(struct snull_priv), "sn%d",
            snull_init);
    snull_devs[1] = alloc_netdev(sizeof(struct snull_priv), "sn%d",
            snull_init);
    if (snull_devs[0] == NULL || snull_devs[1] == NULL)
        goto out;

    ret = -ENODEV;
    for (i = 0; i < 2;  i++)
        if ((result = register_netdev(snull_devs[i])))
            printk("snull: error %i registering device \"%s\"\n",
                    result, snull_devs[i]->name);
        else
            ret = 0;
out:
    if (ret) 
        snull_cleanup();
    return ret;
}


module_init(snull_init_module);
module_exit(snull_cleanup);
