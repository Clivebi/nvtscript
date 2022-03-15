if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.3316.1" );
	script_cve_id( "CVE-2019-0154", "CVE-2019-14895", "CVE-2019-14901", "CVE-2019-15213", "CVE-2019-15916", "CVE-2019-16231", "CVE-2019-18660", "CVE-2019-18683", "CVE-2019-18809", "CVE-2019-19049", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19060", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19077", "CVE-2019-19227", "CVE-2019-19332", "CVE-2019-19338", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19526", "CVE-2019-19527", "CVE-2019-19528", "CVE-2019-19529", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19535", "CVE-2019-19536", "CVE-2019-19537", "CVE-2019-19543" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-12 16:15:00 +0000 (Thu, 12 Dec 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:3316-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:3316-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20193316-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:3316-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP4 kernel-azure was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-19051: There was a memory leak in the
 i2400m_op_rfkill_sw_toggle() function in
 drivers/net/wimax/i2400m/op-rfkill.c in the Linux kernel allowed
 attackers to cause a denial of service (memory consumption)
 (bnc#1159024).

CVE-2019-19338: There was an incomplete fix for Transaction Asynchronous
 Abort (TAA) (bnc#1158954).

CVE-2019-19332: There was an OOB memory write via
 kvm_dev_ioctl_get_cpuid (bnc#1158827).

CVE-2019-19537: There was a race condition bug that can be caused by a
 malicious USB device in the USB character device driver layer
 (bnc#1158904).

CVE-2019-19535: There was an info-leak bug that can be caused by a
 malicious USB device in the drivers/net/can/usb/peak_usb/pcan_usb_fd.c
 driver (bnc#1158903).

CVE-2019-19527: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/hid/usbhid/hiddev.c driver
 (bnc#1158900).

CVE-2019-19526: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/nfc/pn533/usb.c driver (bnc#1158893).

CVE-2019-19533: There was an info-leak bug that can be caused by a
 malicious USB device in the drivers/media/usb/ttusb-dec/ttusb_dec.c
 driver (bnc#1158834).

CVE-2019-19532: There were multiple out-of-bounds write bugs that can be
 caused by a malicious USB device in the Linux kernel HID drivers
 (bnc#1158824).

CVE-2019-19523: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/usb/misc/adutux.c driver, aka
 CID-44efc269db79 (bnc#1158381 1158823 1158834).

CVE-2019-15213: There was a use-after-free caused by a malicious USB
 device in the drivers/media/usb/dvb-usb/dvb-usb-init.c driver
 (bnc#1146544).

CVE-2019-19531: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/usb/misc/yurex.c driver
 (bnc#1158445).

CVE-2019-19543: There was a use-after-free in serial_ir_init_module() in
 drivers/media/rc/serial_ir.c (bnc#1158427).

CVE-2019-19525: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/net/ieee802154/atusb.c driver
 (bnc#1158417).

CVE-2019-19530: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/usb/class/cdc-acm.c driver
 (bnc#1158410).

CVE-2019-19536: There was an info-leak bug that can be caused by a
 malicious USB device in the drivers/net/can/usb/peak_usb/pcan_usb_pro.c
 driver (bnc#1158394).

CVE-2019-19524: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/input/ff-memless.c driver
 (bnc#1158413).

CVE-2019-19528: There was a use-after-free bug that can be caused by a
 malicious USB device in the drivers/usb/misc/iowarrior.c driver
 (bnc#1158407).

CVE-2019-19534: There was an info-leak bug that ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.12.14~6.34.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.12.14~6.34.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.12.14~6.34.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.12.14~6.34.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.12.14~6.34.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.12.14~6.34.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.12.14~6.34.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.12.14~6.34.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.12.14~6.34.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

