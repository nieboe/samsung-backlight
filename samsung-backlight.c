/*
 * Samsung Laptop Backlight driver
 *
 * Copyright (C) 2009 Greg Kroah-Hartman (gregkh@suse.de)
 * Copyright (C) 2009 Novell Inc.
 * Modified 2010 Kobelkov Sergey (sergeyko81@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/backlight.h>
#include <linux/fb.h>
#include <linux/dmi.h>
#include <linux/version.h>

#define MAX_BRIGHT	0xff
#define OFFSET		0xf4

#define SABI_MAX_BRIGHT     0x07

#define SABI_GET_BRIGHTNESS            0x10
#define SABI_SET_BRIGHTNESS            0x11

#define SABI_GET_BACKLIGHT             0x2d
#define SABI_SET_BACKLIGHT             0x2e

static int offset = OFFSET;
module_param(offset, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(offset, "The offset into the PCI device for the brightness control");
static int debug = 0;
module_param(debug, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Verbose output");
static int use_sabi = 1;
module_param(use_sabi, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(use_sabi, "Use SABI to control brightness");
static int force = 0;
module_param(force, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(force, "Skip model/vendor check");


static struct pci_dev *pci_device;
static struct backlight_device *backlight_device;

/*
 * SABI HEADER in low memory (f0000)
 * We need to poke through memory to find a signature in order to find the
 * exact location of this structure.
 */
struct sabi_header {
    u16 port;
    u8 iface_func;
    u8 en_mem;
    u8 re_mem;
    u16 data_offset;
    u16 data_segment;
    u8 bios_ifver;
    u8 launcher_string;
} __attribute__((packed));

/*
 * The SABI interface that we use to write and read values from the system.
 * It is found by looking at the data_offset and data_segment values in the sabi
 * header structure
 */
struct sabi_interface {
    u16 mainfunc;
    u16 subfunc;
    u8 complete;
    u8 retval[20];
} __attribute__((packed));

/* Structure to get data back to the calling function */
struct sabi_retval {
    u8 retval[4];
};

static struct sabi_header __iomem *sabi;
static struct sabi_interface __iomem *sabi_iface;
static void __iomem *f0000_segment;
static struct mutex sabi_mutex;

int sabi_exec_command(u8 command, u8 data, struct sabi_retval *sretval)
{
    int retval = 0;
    
    mutex_lock(&sabi_mutex);

    /* enable memory to be able to write to it */
    outb(readb(&sabi->en_mem), readw(&sabi->port));

    /* write out the command */
    writew(0x5843, &sabi_iface->mainfunc);
    writew(command, &sabi_iface->subfunc);
    writeb(0, &sabi_iface->complete);
    writeb(data, &sabi_iface->retval[0]);
    outb(readb(&sabi->iface_func), readw(&sabi->port));

    /* sleep for a bit to let the command complete */
    msleep(10);

    /* write protect memory to make it safe */
    outb(readb(&sabi->re_mem), readw(&sabi->port));

    /* see if the command actually succeeded */
    if (readb(&sabi_iface->complete) == 0xaa &&
        readb(&sabi_iface->retval[0]) != 0xff) {
        if (sretval) {
            sretval->retval[0] = readb(&sabi_iface->retval[0]);
            sretval->retval[1] = readb(&sabi_iface->retval[1]);
            sretval->retval[2] = readb(&sabi_iface->retval[2]);
            sretval->retval[3] = readb(&sabi_iface->retval[3]);
        }
    }
    else {
        /* Something bad happened, so report it and error out */
        printk(KERN_WARNING "SABI command 0x%02x failed with completion flag 0x%02x and output 0x%02x\n",
            command, readb(&sabi_iface->complete),
        readb(&sabi_iface->retval[0]));
        retval = -EINVAL;
    }
    mutex_unlock(&sabi_mutex);
    return retval;
}


static u8 read_brightness(void)
{
	u8 brightness;
        if(use_sabi){
          struct sabi_retval sretval;    
          brightness=0;
          if (!sabi_exec_command(SABI_GET_BRIGHTNESS, 0, &sretval)) {
            brightness = sretval.retval[0];
            if (brightness != 0)
              --brightness;
          }
        } else {
	  pci_read_config_byte(pci_device, offset, &brightness);
        }
	return brightness;
}

static void set_brightness(u8 brightness)
{
	if(use_sabi)
          sabi_exec_command(SABI_SET_BRIGHTNESS, brightness + 1, NULL);
	else
          pci_write_config_byte(pci_device, offset, brightness);
}

static int get_brightness(struct backlight_device *bd)
{
        return read_brightness();
	//return bd->props.brightness;
}

static int update_status(struct backlight_device *bd)
{
	set_brightness(bd->props.brightness);
	return 0;
}

static struct backlight_ops backlight_ops = {
	.get_brightness	= get_brightness,
	.update_status	= update_status,
};

static int __init dmi_check_cb(const struct dmi_system_id *id)
{
	printk(KERN_INFO KBUILD_MODNAME ": found laptop model '%s'\n",
		id->ident);
	return 0;
}

static struct dmi_system_id __initdata samsung_dmi_table[] = {
	{
		.ident = "N120",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "SAMSUNG ELECTRONICS CO., LTD."),
			DMI_MATCH(DMI_PRODUCT_NAME, "N120"),
			DMI_MATCH(DMI_BOARD_NAME, "N120"),
		},
		.callback = dmi_check_cb,
	},
	{
		.ident = "N130",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "SAMSUNG ELECTRONICS CO., LTD."),
			DMI_MATCH(DMI_PRODUCT_NAME, "N130"),
			DMI_MATCH(DMI_BOARD_NAME, "N130"),
		},
		.callback = dmi_check_cb,
	},
	{
		.ident = "NC10",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "SAMSUNG ELECTRONICS CO., LTD."),
			DMI_MATCH(DMI_PRODUCT_NAME, "NC10"),
			DMI_MATCH(DMI_BOARD_NAME, "NC10"),
		},
		.callback = dmi_check_cb,
	},
	{
		.ident = "X360",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "SAMSUNG ELECTRONICS CO., LTD."),
			DMI_MATCH(DMI_PRODUCT_NAME, "X360"),
			DMI_MATCH(DMI_BOARD_NAME, "X360"),
		},
		.callback = dmi_check_cb,
	},
	{
		.ident = "R518",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "SAMSUNG ELECTRONICS CO., LTD."),
			DMI_MATCH(DMI_PRODUCT_NAME, "R518"),
			DMI_MATCH(DMI_BOARD_NAME, "R518"),
		},
		.callback = dmi_check_cb,
	},
	{
		.ident = "NP-Q45",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "SAMSUNG ELECTRONICS CO., LTD."),
			DMI_MATCH(DMI_PRODUCT_NAME, "SQ45S70S"),
			DMI_MATCH(DMI_BOARD_NAME, "SQ45S70S"),
		},
		.callback = dmi_check_cb,
	},
        {
		.ident = "N150/N210/N220",
		.matches = {
			DMI_MATCH(DMI_SYS_VENDOR, "SAMSUNG ELECTRONICS CO., LTD."),
			DMI_MATCH(DMI_PRODUCT_NAME, "N150/N210/N220"),
			DMI_MATCH(DMI_BOARD_NAME, "N150/N210/N220"),
		},
		.callback = dmi_check_cb,
        },
        {
                .ident = "R530/R730",
                .matches = {
                      DMI_MATCH(DMI_SYS_VENDOR, "SAMSUNG ELECTRONICS CO., LTD."),
                      DMI_MATCH(DMI_PRODUCT_NAME, "R530/R730"),
                      DMI_MATCH(DMI_BOARD_NAME, "R530/R730"),
                },
                .callback = dmi_check_cb,
        },
	{ },
};

static struct dmi_system_id __initdata samsung_sabi_dmi_table[] = {
    {
        .ident = "Samsung",
        .matches = {
            DMI_MATCH(DMI_SYS_VENDOR, "SAMSUNG ELECTRONICS CO., LTD."),
        },
        .callback = NULL,
    },
    { },
};


static int __init samsung_init(void)
{
        struct device *parent=NULL;	

	if (use_sabi && !dmi_check_system(samsung_sabi_dmi_table) && !force){
	    printk(KERN_ERR "Samsung-backlight is intended to work only with Samsung laptops.\n");
	    return -ENODEV;
	}
        if (!use_sabi && !dmi_check_system(samsung_dmi_table) && !force){
	    printk(KERN_ERR "Sorry, your laptop is not supported. Try use_sabi=1\n");
	    return -ENODEV;
        }

        if(use_sabi){
	    const char *test_str = "SwSmi@";
	    int pos;
	    int index = 0;
	    void __iomem *base;
	    unsigned int ifaceP;
	
	    mutex_init(&sabi_mutex);
	
	    f0000_segment = ioremap(0xf0000, 0xffff);
	    if (!f0000_segment) {
	        printk(KERN_ERR "Samsung-backlight: Can't map the segment at 0xf0000\n");
	        return -EINVAL;
	    }
	
	    printk(KERN_INFO "Samsung-backlight: checking for SABI support.\n");
	
	    /* Try to find the signature "SwSmi@" in memory to find the header */
	    base = f0000_segment;
	    for (pos = 0; pos < 0xffff; ++pos) {
	        char temp = readb(base + pos);
	        if (temp == test_str[index]) {
	            if (5 == index++)
	                break;
	        }
	        else {
	            index = 0;
	        }
	    }
	    if (pos == 0xffff) {
	        printk(KERN_INFO "Samsung-backlight: SABI is not supported\n");
	        iounmap(f0000_segment);
	        return -EINVAL;
	    }
	
	    sabi = (struct sabi_header __iomem *)(base + pos + 1);
	
	    printk(KERN_INFO "Samsung-backlight: SABI is supported (%x)\n", pos + 0xf0000 - 6);
	    if (debug) {
	        printk(KERN_DEBUG "SABI header:\n");
	        printk(KERN_DEBUG " SMI Port Number = 0x%04x\n", readw(&sabi->port));
	        printk(KERN_DEBUG " SMI Interface Function = 0x%02x\n", readb(&sabi->iface_func));
	        printk(KERN_DEBUG " SMI enable memory buffer = 0x%02x\n", readb(&sabi->en_mem));
	        printk(KERN_DEBUG " SMI restore memory buffer = 0x%02x\n", readb(&sabi->re_mem));
	        printk(KERN_DEBUG " SABI data offset = 0x%04x\n", readw(&sabi->data_offset));
	        printk(KERN_DEBUG " SABI data segment = 0x%04x\n", readw(&sabi->data_segment));
	        printk(KERN_DEBUG " BIOS interface version = 0x%02x\n", readb(&sabi->bios_ifver));
	        printk(KERN_DEBUG " KBD Launcher string = 0x%02x\n", readb(&sabi->launcher_string));
	    }
	
	    /* Get a pointer to the SABI Interface */
	    ifaceP = (readw(&sabi->data_segment) & 0x0ffff) << 4;
	    ifaceP += readw(&sabi->data_offset) & 0x0ffff;
	    sabi_iface = (struct sabi_interface __iomem *)ioremap(ifaceP, 16);
	    if (!sabi_iface) {
	        printk(KERN_ERR "Samsung-backlight: Can't remap %x\n", ifaceP);
	        iounmap(f0000_segment);
	        return -EINVAL;
	    }
	
	    if (debug) {
	        printk(KERN_DEBUG "Samsung-backlight: SABI Interface = %p\n", sabi_iface);
	    }
        }else{
          /*
	   * The Samsung N120, N130, and NC10 use pci device id 0x27ae, while the
	   * NP-Q45 uses 0x2a02.  Odds are we might need to add more to the
	   * list over time...
	   */
          int pcidevids[]={0x27ae,0x2a02,0x2a42,0xa011,0};
	  int i;
          for(i=0, pci_device=NULL;pcidevids[i]>0 && pci_device==NULL;++i)
	    pci_device = pci_get_device(PCI_VENDOR_ID_INTEL, pcidevids[i], NULL);
          if (!pci_device)
            return -ENODEV;
          parent=&pci_device->dev;
        }
 
        /* create a backlight device to talk to this one */
#if LINUX_VERSION_CODE>=KERNEL_VERSION(2,6,34)
	backlight_device = backlight_device_register("samsung",
						     parent,
						     NULL, &backlight_ops,NULL);
#else
	backlight_device = backlight_device_register("samsung",
						     parent,
						     NULL, &backlight_ops);
#endif
	if (IS_ERR(backlight_device)) {
                if(pci_device)
		  pci_dev_put(pci_device);
		return PTR_ERR(backlight_device);
	}

	backlight_device->props.max_brightness = use_sabi ? SABI_MAX_BRIGHT : MAX_BRIGHT;
	backlight_device->props.brightness = read_brightness();
	backlight_device->props.power = FB_BLANK_UNBLANK;
	backlight_update_status(backlight_device);

	return 0;
}

static void __exit samsung_exit(void)
{
	backlight_device_unregister(backlight_device);
      	if(use_sabi){
     		iounmap(sabi_iface);
      		iounmap(f0000_segment);
	}
        /* we are done with the PCI device, put it back */
	if(pci_device)
		pci_dev_put(pci_device);
}

module_init(samsung_init);
module_exit(samsung_exit);

MODULE_AUTHOR("Kobelkov S. <sergeyko81@gmail.com>, based on the work by Greg Kroah-Hartman <gregkh@suse.de>");
MODULE_DESCRIPTION("Samsung Backlight driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("dmi:*:svnSAMSUNGELECTRONICSCO.,LTD.:pn*:*:rn*:*");

