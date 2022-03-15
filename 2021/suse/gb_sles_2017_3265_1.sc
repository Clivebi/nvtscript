if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.3265.1" );
	script_cve_id( "CVE-2017-1000112", "CVE-2017-10661", "CVE-2017-12192", "CVE-2017-12762", "CVE-2017-13080", "CVE-2017-14051", "CVE-2017-14140", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-15102", "CVE-2017-15265", "CVE-2017-15274", "CVE-2017-16525", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16531", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16649", "CVE-2017-8831" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:50 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-06 01:29:00 +0000 (Fri, 06 Apr 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:3265-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0|SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:3265-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20173265-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:3265-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2017-16649: The usbnet_generic_cdc_bind function in
 drivers/net/usb/cdc_ether.c in the Linux kernel allowed local users to
 cause a denial of service (divide-by-zero error and system crash) or
 possibly have unspecified other impact via a crafted USB device
 (bnc#1067085).
- CVE-2017-16535: The usb_get_bos_descriptor function in
 drivers/usb/core/config.c in the Linux kernel allowed local users to
 cause a denial of service (out-of-bounds read and system crash) or
 possibly have unspecified other impact via a crafted USB device
 (bnc#1066700).
- CVE-2017-15102: The tower_probe function in
 drivers/usb/misc/legousbtower.c in the Linux kernel allowed local users
 (who are physically proximate for inserting a crafted USB device) to
 gain privileges by leveraging a write-what-where condition that occurs
 after a race condition and a NULL pointer dereference (bnc#1066705).
- CVE-2017-16531: drivers/usb/core/config.c in the Linux kernel allowed
 local users to cause a denial of service (out-of-bounds read and system
 crash) or possibly have unspecified other impact via a crafted USB
 device, related to the USB_DT_INTERFACE_ASSOCIATION descriptor
 (bnc#1066671).
- CVE-2017-16529: The snd_usb_create_streams function in sound/usb/card.c
 in the Linux kernel allowed local users to cause a denial of service
 (out-of-bounds read and system crash) or possibly have unspecified other
 impact via a crafted USB device (bnc#1066650).
- CVE-2017-16525: The usb_serial_console_disconnect function in
 drivers/usb/serial/console.c in the Linux kernel allowed local users to
 cause a denial of service (use-after-free and system crash) or possibly
 have unspecified other impact via a crafted USB device, related to
 disconnection and failed setup (bnc#1066618).
- CVE-2017-16537: The imon_probe function in drivers/media/rc/imon.c in
 the Linux kernel allowed local users to cause a denial of service (NULL
 pointer dereference and system crash) or possibly have unspecified other
 impact via a crafted USB device (bnc#1066573).
- CVE-2017-16536: The cx231xx_usb_probe function in
 drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux kernel allowed
 local users to cause a denial of service (NULL pointer dereference and
 system crash) or possibly have unspecified other impact via a crafted
 USB device (bnc#1066606).
- CVE-2017-16527: sound/usb/mixer.c in the Linux kernel allowed local
 users to cause a denial of service (snd_usb_mixer_interrupt
 use-after-free and system crash) or possibly have unspecified other
 impact via a crafted USB device (bnc#1066625).
- CVE-2017-13080: Wi-Fi Protected Access (WPA and WPA2) allowed
 reinstallation of the Group Temporal Key (GTK) during the group key
 handshake, allowing an attacker within radio range to replay frames from
 ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-extra", rpm: "kernel-default-extra~3.0.101~108.18.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-extra", rpm: "kernel-pae-extra~3.0.101~108.18.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-extra", rpm: "kernel-ppc64-extra~3.0.101~108.18.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-extra", rpm: "kernel-trace-extra~3.0.101~108.18.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-extra", rpm: "kernel-xen-extra~3.0.101~108.18.1", rls: "SLES11.0" ) )){
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigmem", rpm: "kernel-bigmem~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigmem-base", rpm: "kernel-bigmem-base~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigmem-devel", rpm: "kernel-bigmem-devel~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-base", rpm: "kernel-ec2-base~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae", rpm: "kernel-pae~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-base", rpm: "kernel-pae-base~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-devel", rpm: "kernel-pae-devel~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64", rpm: "kernel-ppc64~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-base", rpm: "kernel-ppc64-base~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-devel", rpm: "kernel-ppc64-devel~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace", rpm: "kernel-trace~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-base", rpm: "kernel-trace-base~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-devel", rpm: "kernel-trace-devel~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.0.101~108.18.1", rls: "SLES11.0SP4" ) )){
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

