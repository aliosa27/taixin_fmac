#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

MODULE_INFO(intree, "Y");

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x1899fedf, "filp_open" },
	{ 0xe914e41e, "strcpy" },
	{ 0xc5db3f1b, "usb_alloc_urb" },
	{ 0xc6d09aa9, "release_firmware" },
	{ 0x92e683f5, "down_timeout" },
	{ 0x49cd25ed, "alloc_workqueue" },
	{ 0x5b7143fb, "usb_free_urb" },
	{ 0x4a3ad70e, "wait_for_completion_timeout" },
	{ 0x2eabd6a3, "eth_mac_addr" },
	{ 0xac782a56, "skb_put" },
	{ 0x7f02188f, "__msecs_to_jiffies" },
	{ 0xa3324301, "consume_skb" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xa6257a2f, "complete" },
	{ 0xc5b6f236, "queue_work_on" },
	{ 0xb742fd7, "simple_strtol" },
	{ 0x7cb3f618, "unregister_netdev" },
	{ 0xc47c6684, "skb_dequeue" },
	{ 0x608741b5, "__init_swait_queue_head" },
	{ 0x1076ab81, "request_firmware" },
	{ 0x9839c1f2, "usb_register_driver" },
	{ 0xcf2a6966, "up" },
	{ 0x4829a47e, "memcpy" },
	{ 0x37a0cba, "kfree" },
	{ 0x8cc68fe1, "seq_lseek" },
	{ 0x51fbd779, "proc_create_data" },
	{ 0x82ee90dc, "timer_delete_sync" },
	{ 0x34db050b, "_raw_spin_lock_irqsave" },
	{ 0xaf6a15cf, "ether_setup" },
	{ 0x21cbb2cd, "eth_type_trans" },
	{ 0x19e2bc35, "alloc_netdev_mqs" },
	{ 0x122c3a7e, "_printk" },
	{ 0x96b29254, "strncasecmp" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x6cbbfc54, "__arch_copy_to_user" },
	{ 0xe8499eb0, "usb_get_dev" },
	{ 0xa5ac830b, "usb_submit_urb" },
	{ 0xb7f99008, "skb_copy_expand" },
	{ 0xbe4a7ec5, "skb_queue_tail" },
	{ 0xfcdfef7a, "skb_pull" },
	{ 0xc38c83b8, "mod_timer" },
	{ 0x1e6d26a8, "strstr" },
	{ 0x437c62b4, "kfree_skb_reason" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0xeccae64b, "skb_push" },
	{ 0xb499da7d, "register_netdev" },
	{ 0xaafdc258, "strcasecmp" },
	{ 0x36054e7f, "free_netdev" },
	{ 0xbcab6ee6, "sscanf" },
	{ 0x4430cc6d, "usb_deregister" },
	{ 0x37befc70, "jiffies_to_msecs" },
	{ 0xd35cce70, "_raw_spin_unlock_irqrestore" },
	{ 0x36e75c74, "proc_mkdir" },
	{ 0xdcb764ad, "memset" },
	{ 0x18bcd516, "param_ops_charp" },
	{ 0x4003c220, "kernel_read" },
	{ 0x9166fc03, "__flush_workqueue" },
	{ 0xda506aa7, "netif_rx" },
	{ 0x10569bf5, "__netdev_alloc_skb" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x15ba50a6, "jiffies" },
	{ 0x6ecf9493, "usb_unlink_urb" },
	{ 0x6a8b0722, "seq_read" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0x85df9b6c, "strsep" },
	{ 0xc6f46339, "init_timer_key" },
	{ 0x89fa9616, "filp_close" },
	{ 0x5c674bce, "seq_write" },
	{ 0x8730a28, "remove_proc_entry" },
	{ 0x5bc5126c, "usb_kill_urb" },
	{ 0x3c12dfe, "cancel_work_sync" },
	{ 0xfb9fde1a, "seq_printf" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x12a4e128, "__arch_copy_from_user" },
	{ 0x3434f437, "single_release" },
	{ 0xa65c6def, "alt_cb_patch_nops" },
	{ 0xeaf73241, "kmalloc_trace" },
	{ 0x98cf60b3, "strlen" },
	{ 0x4480fffa, "dev_kfree_skb_any_reason" },
	{ 0xf5bdfeca, "param_ops_int" },
	{ 0xe8d4d0c8, "single_open" },
	{ 0x349cba85, "strchr" },
	{ 0xf9a482f9, "msleep" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x3763ab95, "kmalloc_caches" },
	{ 0xa9d39115, "skb_queue_head" },
	{ 0x2d3385d3, "system_wq" },
	{ 0xe478ef45, "module_layout" },
};

MODULE_INFO(depends, "");

MODULE_ALIAS("usb:vA012p4002d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:vA012p4104d*dc*dsc*dp*ic*isc*ip*in*");
MODULE_ALIAS("usb:vA012p8400d*dc*dsc*dp*ic*isc*ip*in*");

MODULE_INFO(srcversion, "EBE5EAAD330FD24C8BEB170");
