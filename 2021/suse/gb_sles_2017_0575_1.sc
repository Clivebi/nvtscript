if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.0575.1" );
	script_cve_id( "CVE-2015-8709", "CVE-2016-7117", "CVE-2016-9806", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5551", "CVE-2017-5576", "CVE-2017-5577", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-5986" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:0575-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:0575-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20170575-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:0575-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.49 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2016-7117: Use-after-free vulnerability in the __sys_recvmmsg
 function in net/socket.c in the Linux kernel allowed remote attackers to
 execute arbitrary code via vectors involving a recvmmsg system call that
 was mishandled during error processing (bnc#1003077).
- CVE-2017-5576: Integer overflow in the vc4_get_bcl function in
 drivers/gpu/drm/vc4/vc4_gem.c in the VideoCore DRM driver in the Linux
 kernel allowed local users to cause a denial of service or possibly have
 unspecified
 other impact via a crafted size value in a VC4_SUBMIT_CL ioctl call
 (bnc#1021294).
- CVE-2017-5577: The vc4_get_bcl function in drivers/gpu/drm/vc4/vc4_gem.c
 in the VideoCore DRM driver in the Linux kernel did not set an errno
 value upon certain overflow detections, which allowed local users to
 cause a denial of service (incorrect pointer dereference and OOPS) via
 inconsistent size values in a VC4_SUBMIT_CL ioctl call (bnc#1021294).
- CVE-2017-5551: The simple_set_acl function in fs/posix_acl.c in the
 Linux kernel preserved the setgid bit during a setxattr call involving a
 tmpfs filesystem, which allowed local users to gain group privileges by
 leveraging the existence of a setgid program with restrictions on
 execute permissions. (bnc#1021258).
- CVE-2017-2583: The load_segment_descriptor implementation in
 arch/x86/kvm/emulate.c in the Linux kernel improperly emulated a 'MOV
 SS, NULL selector' instruction, which allowed guest OS users to cause a
 denial of service (guest OS crash) or gain guest OS privileges via a
 crafted application (bnc#1020602).
- CVE-2017-2584: arch/x86/kvm/emulate.c in the Linux kernel allowed local
 users to obtain sensitive information from kernel memory or cause a
 denial of service (use-after-free) via a crafted application that
 leverages instruction emulation for fxrstor, fxsave, sgdt, and sidt
 (bnc#1019851).
- CVE-2015-8709: kernel/ptrace.c in the Linux kernel mishandled uid and
 gid mappings, which allowed local users to gain privileges by
 establishing a user namespace, waiting for a root process to enter that
 namespace with an unsafe uid or gid, and then using the ptrace system
 call. NOTE: the vendor states 'there is no kernel bug here'
 (bnc#1010933).
- CVE-2016-9806: Race condition in the netlink_dump function in
 net/netlink/af_netlink.c in the Linux kernel allowed local users to
 cause a denial of service (double free) or possibly have unspecified
 other impact via a crafted application that made sendmsg system calls,
 leading to a free
 operation associated with a new dump that started earlier than
 anticipated (bnc#1013540).
- CVE-2017-5897: fixed a bug in the Linux kernel IPv6 implementation which
 allowed remote attackers to trigger an out-of-bounds access, leading to
 a denial-of-service ... [Please see the references for more information on the vulnerabilities]" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.49~92.11.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.49~92.11.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.49~92.11.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.49~92.11.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.49~92.11.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.49~92.11.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.49~92.11.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.49~92.11.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.49~92.11.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.49~92.11.1", rls: "SLES12.0SP2" ) )){
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

