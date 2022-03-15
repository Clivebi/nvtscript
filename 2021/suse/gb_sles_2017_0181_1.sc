if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.0181.1" );
	script_cve_id( "CVE-2015-1350", "CVE-2015-8964", "CVE-2016-7039", "CVE-2016-7042", "CVE-2016-7425", "CVE-2016-7913", "CVE-2016-7917", "CVE-2016-8645", "CVE-2016-8666", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9793", "CVE-2016-9919" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-07 03:00:00 +0000 (Sat, 07 Jan 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:0181-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:0181-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20170181-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:0181-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.38 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2015-1350: The VFS subsystem in the Linux kernel 3.x provides an
 incomplete set of requirements for setattr operations that
 underspecifies removing extended privilege attributes, which allowed
 local users to cause a denial of service (capability stripping) via a
 failed invocation of a system call, as demonstrated by using chown to
 remove a capability from the ping or Wireshark dumpcap program
 (bnc#914939).
- CVE-2015-8964: The tty_set_termios_ldisc function in
 drivers/tty/tty_ldisc.c in the Linux kernel allowed local users to
 obtain sensitive information from kernel memory by reading a tty data
 structure (bnc#1010507).
- CVE-2016-7039: The IP stack in the Linux kernel allowed remote attackers
 to cause a denial of service (stack consumption and panic) or possibly
 have unspecified other impact by triggering use of the GRO path for
 large crafted packets, as demonstrated by packets that contain only VLAN
 headers, a related issue to CVE-2016-8666 (bnc#1001486).
- CVE-2016-7042: The proc_keys_show function in security/keys/proc.c in
 the Linux kernel through 4.8.2, when the GNU Compiler Collection (gcc)
 stack protector is enabled, uses an incorrect buffer size for certain
 timeout data, which allowed local users to cause a denial of service
 (stack memory corruption and panic) by reading the /proc/keys file
 (bnc#1004517).
- CVE-2016-7425: The arcmsr_iop_message_xfer function in
 drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did not restrict a
 certain length field, which allowed local users to gain privileges or
 cause a denial of service (heap-based buffer overflow) via an
 ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).
- CVE-2016-7913: The xc2028_set_config function in
 drivers/media/tuners/tuner-xc2028.c in the Linux kernel allowed local
 users to gain privileges or cause a denial of service (use-after-free)
 via vectors involving omission of the firmware name from a certain data
 structure (bnc#1010478).
- CVE-2016-7917: The nfnetlink_rcv_batch function in
 net/netfilter/nfnetlink.c in the Linux kernel did not check whether a
 batch message's length field is large enough, which allowed local users
 to obtain sensitive information from kernel memory or cause a denial of
 service (infinite loop or out-of-bounds read) by leveraging the
 CAP_NET_ADMIN capability (bnc#1010444).
- CVE-2016-8645: The TCP stack in the Linux kernel mishandled skb
 truncation, which allowed local users to cause a denial of service
 (system crash) via a crafted application that made sendto system calls,
 related to net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c (bnc#1009969).
- CVE-2016-8666: The IP stack in the Linux kernel allowed remote attackers
 to cause a denial of service (stack consumption and panic) or possibly
 ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise High Availability 12-SP2, SUSE Linux Enterprise Live Patching 12, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Workstation Extension 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.38~93.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.38~93.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.38~93.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.38~93.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.38~93.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.38~93.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.38~93.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.38~93.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.38~93.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.38~93.1", rls: "SLES12.0SP2" ) )){
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

