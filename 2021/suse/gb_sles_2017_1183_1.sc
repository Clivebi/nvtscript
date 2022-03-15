if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1183.1" );
	script_cve_id( "CVE-2016-10200", "CVE-2016-2117", "CVE-2016-9191", "CVE-2017-2596", "CVE-2017-2671", "CVE-2017-5986", "CVE-2017-6074", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6347", "CVE-2017-6353", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7374" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-19 01:29:00 +0000 (Thu, 19 Jul 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1183-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1183-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171183-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:1183-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.58 to receive various security and bugfixes.
Notable new/improved features:
- Improved support for Hyper-V
- Support for Matrox G200eH3
- Support for tcp_westwood The following security bugs were fixed:
- CVE-2017-2671: The ping_unhash function in net/ipv4/ping.c in the Linux
 kernel was too late in obtaining a certain lock and consequently could
 not ensure that disconnect function calls are safe, which allowed local
 users to cause a denial of service (panic) by leveraging access to the
 protocol value of IPPROTO_ICMP in a socket system call (bnc#1031003).
- CVE-2017-7308: The packet_set_ring function in net/packet/af_packet.c in
 the Linux kernel did not properly validate certain block-size data,
 which allowed local users to cause a denial of service (overflow) or
 possibly have unspecified other impact via crafted system calls
 (bnc#1031579).
- CVE-2017-7294: The vmw_surface_define_ioctl function in
 drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux kernel did not
 validate addition of certain levels data, which allowed local users to
 trigger an integer overflow and out-of-bounds write, and cause a denial
 of service (system hang or crash) or possibly gain privileges, via a
 crafted ioctl call for a /dev/dri/renderD* device (bnc#1031440).
- CVE-2017-7261: The vmw_surface_define_ioctl function in
 drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux kernel did not
 check for a zero value of certain levels data, which allowed local users
 to cause a denial of service (ZERO_SIZE_PTR dereference, and GPF and
 possibly panic) via a crafted ioctl call for a /dev/dri/renderD* device
 (bnc#1031052).
- CVE-2017-7187: The sg_ioctl function in drivers/scsi/sg.c in the Linux
 kernel allowed local users to cause a denial of service (stack-based
 buffer overflow) or possibly have unspecified other impact via a large
 command size in an SG_NEXT_CMD_LEN ioctl call, leading to out-of-bounds
 write access in the sg_write function (bnc#1030213).
- CVE-2017-7374: Use-after-free vulnerability in fs/crypto/ in the Linux
 kernel allowed local users to cause a denial of service (NULL pointer
 dereference) or possibly gain privileges by revoking keyring keys being
 used for ext4, f2fs, or ubifs encryption, causing cryptographic
 transform objects to be freed prematurely (bnc#1032006).
- CVE-2016-10200: Race condition in the L2TPv3 IP Encapsulation feature in
 the Linux kernel allowed local users to gain privileges or cause a
 denial of service (use-after-free) by making multiple bind system calls
 without properly ascertaining whether a socket has the SOCK_ZAPPED
 status, related to net/l2tp/l2tp_ip.c and net/l2tp/l2tp_ip6.c
 (bnc#1028415).
- CVE-2017-6345: The LLC subsystem in the Linux kernel did not ensure that
 a certain destructor exists in required circumstances, which allowed
 local users to cause a denial of service ... [Please see the references for more information on the vulnerabilities]" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.59~92.17.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.59~92.17.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.59~92.17.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.59~92.17.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.59~92.17.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.59~92.17.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.59~92.17.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.59~92.17.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.59~92.17.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.59~92.17.2", rls: "SLES12.0SP2" ) )){
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

