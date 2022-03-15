if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1678.1" );
	script_cve_id( "CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-0777", "CVE-2015-1420", "CVE-2015-1805", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-4167", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5707", "CVE-2015-6252" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:11 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1678-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0|SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1678-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151678-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-source' package(s) announced via the SUSE-SU-2015:1678-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.
Following security bugs were fixed:
* CVE-2015-6252: Possible file descriptor leak for each
 VHOST_SET_LOG_FDcommand issued, this could eventually wasting available
 system resources and creating a denial of service (bsc#942367).
* CVE-2015-5707: Possible integer overflow in the calculation of total
 number of pages in bio_map_user_iov() (bsc#940338).
* CVE-2015-5364: The (1) udp_recvmsg and (2) udpv6_recvmsg functions in
 the Linux kernel before 4.0.6 do not properly consider yielding a
 processor, which allowed remote attackers to cause a denial of service
 (system hang) via incorrect checksums within a UDP packet flood
 (bsc#936831).
* CVE-2015-5366: The (1) udp_recvmsg and (2) udpv6_recvmsg functions in
 the Linux kernel before 4.0.6 provide inappropriate -EAGAIN return
 values, which allowed remote attackers to cause a denial of service
 (EPOLLET epoll application read outage) via an incorrect checksum in a
 UDP packet, a different vulnerability than CVE-2015-5364 (bsc#936831).
* CVE-2015-1420: Race condition in the handle_to_path function in
 fs/fhandle.c in the Linux kernel through 3.19.1 allowed local users to
 bypass intended size restrictions and trigger read operations on
 additional memory locations by changing the handle_bytes value of a file
 handle during the execution of this function (bsc#915517).
* CVE-2015-1805: The (1) pipe_read and (2) pipe_write implementations in
 fs/pipe.c in the Linux kernel before 3.16 do not properly consider the
 side effects of failed __copy_to_user_inatomic and
 __copy_from_user_inatomic calls, which allows local users to cause a
 denial of service (system crash) or possibly gain privileges via a
 crafted application, aka an 'I/O' vector array overrun. (bsc#933429)
* CVE-2015-2150: Xen 3.3.x through 4.5.x and the Linux kernel through
 3.19.1 do not properly restrict access to PCI command registers, which
 might allow local guest users to cause a denial of service (non-maskable
 interrupt and host crash) by disabling the (1) memory or (2) I/O
 decoding for a PCI Express device and then accessing the device, which
 triggers an Unsupported Request (UR) response. (bsc#919463)
* CVE-2015-2830: arch/x86/kernel/entry_64.S in the Linux kernel before
 3.19.2 does not prevent the TS_COMPAT flag from reaching a user-mode
 task, which might allow local users to bypass the seccomp or audit
 protection mechanism via a crafted application that uses the (1) fork
 or (2) close system call, as demonstrated by an attack against seccomp
 before 3.16. (bsc#926240)
* CVE-2015-4700: The bpf_int_jit_compile function in
 arch/x86/net/bpf_jit_comp.c in the Linux kernel before 4.0.6 allowed
 local users to cause a denial of service (system crash) by creating a
 packet filter and then loading crafted BPF instructions that trigger
 late convergence by the JIT ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'kernel-source' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-extra", rpm: "kernel-default-extra~3.0.101~65.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-extra", rpm: "kernel-pae-extra~3.0.101~65.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-extra", rpm: "kernel-ppc64-extra~3.0.101~65.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-extra", rpm: "kernel-trace-extra~3.0.101~65.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-extra", rpm: "kernel-xen-extra~3.0.101~65.1", rls: "SLES11.0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-base", rpm: "kernel-ec2-base~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae", rpm: "kernel-pae~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-base", rpm: "kernel-pae-base~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-devel", rpm: "kernel-pae-devel~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64", rpm: "kernel-ppc64~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-base", rpm: "kernel-ppc64-base~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-devel", rpm: "kernel-ppc64-devel~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace", rpm: "kernel-trace~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-base", rpm: "kernel-trace-base~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-devel", rpm: "kernel-trace-devel~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.0.101~65.1", rls: "SLES11.0SP4" ) )){
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

