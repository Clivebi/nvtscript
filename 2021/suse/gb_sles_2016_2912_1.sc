if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2912.1" );
	script_cve_id( "CVE-2015-8956", "CVE-2016-5696", "CVE-2016-6130", "CVE-2016-6327", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7039", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-7425", "CVE-2016-8658", "CVE-2016-8666" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-07 03:00:00 +0000 (Sat, 07 Jan 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2912-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2912-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162912-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:2912-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 kernel was updated to 3.12.67 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2016-7042: The proc_keys_show function in security/keys/proc.c in
 the Linux kernel used an incorrect buffer size for certain timeout data,
 which allowed local users to cause a denial of service (stack memory
 corruption and panic) by reading the /proc/keys file (bsc#1004517).
- CVE-2016-7097: The filesystem implementation in the Linux kernel
 preserved the setgid bit during a setxattr call, which allowed local
 users to gain group privileges by leveraging the existence of a setgid
 program with restrictions on execute permissions (bsc#995968).
- CVE-2015-8956: The rfcomm_sock_bind function in
 net/bluetooth/rfcomm/sock.c in the Linux kernel allowed local users to
 obtain sensitive information or cause a denial of service (NULL pointer
 dereference) via vectors involving a bind system call on a Bluetooth
 RFCOMM socket (bnc#1003925).
- CVE-2016-5696: net/ipv4/tcp_input.c in the Linux kernel did not properly
 determine the rate of challenge ACK segments, which made it easier for
 man-in-the-middle attackers to hijack TCP sessions via a blind in-window
 attack (bnc#989152).
- CVE-2016-6130: Race condition in the sclp_ctl_ioctl_sccb function in
 drivers/s390/char/sclp_ctl.c in the Linux kernel allowed local users to
 obtain sensitive information from kernel memory by changing a certain
 length value, aka a 'double fetch' vulnerability (bnc#987542).
- CVE-2016-6327: drivers/infiniband/ulp/srpt/ib_srpt.c in the Linux kernel
 allowed local users to cause a denial of service (NULL pointer
 dereference and system crash) by using an ABORT_TASK command to abort a
 device write operation (bnc#994748).
- CVE-2016-6480: Race condition in the ioctl_send_fib function in
 drivers/scsi/aacraid/commctrl.c in the Linux kernel allowed local users
 to cause a denial of service (out-of-bounds access or system crash) by
 changing a certain size value, aka a 'double fetch' vulnerability
 (bnc#991608).
- CVE-2016-6828: The tcp_check_send_head function in include/net/tcp.h in
 the Linux kernel did not properly maintain certain SACK state after a
 failed data copy, which allowed local users to cause a denial of service
 (tcp_xmit_retransmit_queue use-after-free and system crash) via a
 crafted SACK option (bnc#994296).
- CVE-2016-7425: The arcmsr_iop_message_xfer function in
 drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did not restrict a
 certain length field, which allowed local users to gain privileges
 or cause a denial of service (heap-based buffer overflow) via an
 ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).
- CVE-2016-8658: Stack-based buffer overflow in the
 brcmf_cfg80211_start_ap function in
 drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c in the Linux
 kernel allowed local users to cause a denial of service ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Live Patching 12, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Workstation Extension 12-SP1." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.12.67~60.64.18.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debuginfo", rpm: "kernel-ec2-debuginfo~3.12.67~60.64.18.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debugsource", rpm: "kernel-ec2-debugsource~3.12.67~60.64.18.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.12.67~60.64.18.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra", rpm: "kernel-ec2-extra~3.12.67~60.64.18.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra-debuginfo", rpm: "kernel-ec2-extra-debuginfo~3.12.67~60.64.18.1", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base-debuginfo", rpm: "kernel-xen-base-debuginfo~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.12.67~60.64.18.1", rls: "SLES12.0SP1" ) )){
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

