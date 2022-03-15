if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1853.1" );
	script_cve_id( "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-7346", "CVE-2017-7487", "CVE-2017-7616", "CVE-2017-7618", "CVE-2017-8890", "CVE-2017-8924", "CVE-2017-8925", "CVE-2017-9074", "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9150", "CVE-2017-9242" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1853-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1853-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171853-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:1853-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.74 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2017-1000365: The Linux Kernel imposes a size restriction on the
 arguments and environmental strings passed through
 RLIMIT_STACK/RLIM_INFINITY (1/4 of the size), but did not take the
 argument and environment pointers into account, which allowed attackers
 to bypass this limitation. (bnc#1039354).
- CVE-2017-1000380: sound/core/timer.c in the Linux kernel is vulnerable
 to a data race in the ALSA /dev/snd/timer driver resulting in local
 users being able to read information belonging to other users, i.e.,
 uninitialized memory contents may be disclosed when a read and an ioctl
 happen at the same time (bnc#1044125).
- CVE-2017-7346: The vmw_gb_surface_define_ioctl function in
 drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux kernel did not
 validate certain levels data, which allowed local users to cause a
 denial of service (system hang) via a crafted ioctl call for a
 /dev/dri/renderD* device (bnc#1031796).
- CVE-2017-9242: The __ip6_append_data function in net/ipv6/ip6_output.c
 in the Linux kernel is too late in checking whether an overwrite of an
 skb data structure may occur, which allowed local users to cause a
 denial of service (system crash) via crafted system calls (bnc#1041431).
- CVE-2017-9076: The dccp_v6_request_recv_sock function in net/dccp/ipv6.c
 in the Linux kernel mishandled inheritance, which allowed local users to
 cause a denial of service or possibly have unspecified other impact via
 crafted system calls, a related issue to CVE-2017-8890 (bnc#1039885).
- CVE-2017-9077: The tcp_v6_syn_recv_sock function in net/ipv6/tcp_ipv6.c
 in the Linux kernel mishandled inheritance, which allowed local users to
 cause a denial of service or possibly have unspecified other impact via
 crafted system calls, a related issue to CVE-2017-8890 (bnc#1040069).
- CVE-2017-9075: The sctp_v6_create_accept_sk function in net/sctp/ipv6.c
 in the Linux kernel mishandled inheritance, which allowed local users to
 cause a denial of service or possibly have unspecified other impact via
 crafted system calls, a related issue to CVE-2017-8890 (bnc#1039883).
- CVE-2017-9074: The IPv6 fragmentation implementation in the Linux kernel
 did not consider that the nexthdr field may be associated with an
 invalid option, which allowed local users to cause a denial of service
 (out-of-bounds read and BUG) or possibly have unspecified other impact
 via crafted socket and send system calls (bnc#1039882).
- CVE-2017-8924: The edge_bulk_in_callback function in
 drivers/usb/serial/io_ti.c in the Linux kernel allowed local users to
 obtain sensitive information (in the dmesg ringbuffer and syslog) from
 uninitialized kernel memory by using a crafted USB device (posing as an
 io_ti USB serial device) to trigger an integer underflow. ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise High Availability 12-SP2, SUSE Linux Enterprise Live Patching 12, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Workstation Extension 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.74~92.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.74~92.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.74~92.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.74~92.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.74~92.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.74~92.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.74~92.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.74~92.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.74~92.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.74~92.29.1", rls: "SLES12.0SP2" ) )){
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

