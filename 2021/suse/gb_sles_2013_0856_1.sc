if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.0856.1" );
	script_cve_id( "CVE-2012-4444", "CVE-2013-1928" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2013-06-15 03:15:00 +0000 (Sat, 15 Jun 2013)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:0856-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:0856-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20130856-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2013:0856-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 10 SP4 kernel has been updated to fix various bugs and security issues.

Security issues fixed:

 *

 CVE-2012-4444: The ip6_frag_queue function in net/ipv6/reassembly.c in the Linux kernel allowed remote attackers to bypass intended network restrictions via overlapping IPv6 fragments.

 *

 CVE-2013-1928: The do_video_set_spu_palette function in fs/compat_ioctl.c in the Linux kernel lacked a certain error check, which might have allowed local users to obtain sensitive information from kernel stack memory via a crafted VIDEO_SET_SPU_PALETTE ioctl call on a /dev/dvb device.

Also the following bugs have been fixed:

 * hugetlb: Fix regression introduced by the original patch (bnc#790236, bnc#819403).
 * NFSv3/v2: Fix data corruption with NFS short reads
(bnc#818337).
 * Fix package descriptions in specfiles (bnc#817666).
 * TTY: fix atime/mtime regression (bnc#815745).
 * virtio_net: ensure big packets are 64k (bnc#760753).
 * virtio_net: refill rx buffers when oom occurs
(bnc#760753).
 * qeth: fix qeth_wait_for_threads() deadlock for OSN devices (bnc#812317, LTC#90910).
 * nfsd: remove unnecessary NULL checks from nfsd_cross_mnt (bnc#810628).
 * knfsd: Fixed problem with NFS exporting directories which are mounted on (bnc#810628).

Security Issue references:

 * CVE-2012-4444
>
 * CVE-2013-1928
>" );
	script_tag( name: "affected", value: "'Linux kernel' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigsmp", rpm: "kernel-bigsmp~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-iseries64", rpm: "kernel-iseries64~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-kdump", rpm: "kernel-kdump~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-kdumppae", rpm: "kernel-kdumppae~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64", rpm: "kernel-ppc64~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-smp", rpm: "kernel-smp~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vmi", rpm: "kernel-vmi~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vmipae", rpm: "kernel-vmipae~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xenpae", rpm: "kernel-xenpae~2.6.16.60~0.103.1", rls: "SLES10.0SP4" ) )){
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

