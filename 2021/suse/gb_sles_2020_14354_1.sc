if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.14354.1" );
	script_cve_id( "CVE-2019-12456", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-15213", "CVE-2019-15916", "CVE-2019-18660", "CVE-2019-18675", "CVE-2019-19066", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19227", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19527", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19537", "CVE-2019-19768", "CVE-2019-19965", "CVE-2019-19966", "CVE-2019-20096", "CVE-2020-10942", "CVE-2020-11608", "CVE-2020-8647", "CVE-2020-8648", "CVE-2020-8649", "CVE-2020-9383" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:04 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-03 11:15:00 +0000 (Fri, 03 Jan 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:14354-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0|SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:14354-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-202014354-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:14354-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-10942: In get_raw_socket in drivers/vhost/net.c lacks
 validation of an sk_family field, which might allow attackers to trigger
 kernel stack corruption via crafted system calls (bsc#1167629).

CVE-2020-8647: There was a use-after-free vulnerability in the
 vc_do_resize function in drivers/tty/vt/vt.c (bsc#1162929).

CVE-2020-8649: There was a use-after-free vulnerability in the
 vgacon_invert_region function in drivers/video/console/vgacon.c
 (bsc#1162931).

CVE-2020-9383: An issue was discovered set_fdc in drivers/block/floppy.c
 leads to a wait_til_ready out-of-bounds read because the FDC index is
 not checked for errors before assigning it (bsc#1165111).

CVE-2019-19768: Fixed a use-after-free in the __blk_add_trace function
 in kernel/trace/blktrace.c (bsc#1159285).

CVE-2020-11608: Fixed a NULL pointer dereferences in
 ov511_mode_init_regs and ov518_mode_init_regs when there are zero
 endpoints (bsc#1168829).

CVE-2020-8648: There was a use-after-free vulnerability in the
 n_tty_receive_buf_common function in drivers/tty/n_tty.c (bsc#1162928).

CVE-2019-14896: A heap-based buffer overflow vulnerability was found in
 Marvell WiFi chip driver. A remote attacker could cause a denial of
 service or possibly execute arbitrary code, when the
 lbs_ibss_join_existing function is called after a STA connects to an AP
 (bsc#1157157).

CVE-2019-14897: A stack-based buffer overflow was found in the Marvell
 WiFi chip driver. An attacker is able to cause a denial of service or
 possibly execute arbitrary code, when a STA works in IBSS mode and
 connects to another STA (bsc#1157155).

CVE-2019-18675: Fixed an Integer Overflow in cpia2_remap_buffer in
 drivers/media/usb/cpia2/cpia2_core.c because cpia2 has its own mmap
 implementation. This allowed local users to obtain read and write
 permissions on kernel physical pages, which can possibly result in a
 privilege escalation (bsc#1157804).

CVE-2019-19965: Fixed a NULL pointer dereference in
 drivers/scsi/libsas/sas_discover.c because of mishandling of port
 disconnection during discovery, related to a PHY down race condition
 (bsc#1159911).

CVE-2019-19066: A memory leak in the bfad_im_get_stats() function in
 drivers/scsi/bfa/bfad_attr.c allowed attackers to cause a denial of
 service by triggering bfa_port_get_stats() failures (bsc#1157303).

CVE-2019-20096: Fixed a memory leak in __feat_register_sp() in
 net/dccp/feat.c, which may cause denial of service (bsc#1159908).

CVE-2019-19966: Fixed a use-after-free in cpia2_exit() in
 drivers/media/usb/cpia2/cpia2_v4l.c that will cause denial of service
 (bsc#1159841).

CVE-2019-19532: Fixed multiple out-of-bounds write bugs that can be
 caused by a malicious USB device (bsc#1158824).

CVE-2019-19523: Fixed a use-after-free bug that can be ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Server 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-extra", rpm: "kernel-default-extra~3.0.101~108.111.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-extra", rpm: "kernel-pae-extra~3.0.101~108.111.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-extra", rpm: "kernel-ppc64-extra~3.0.101~108.111.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-extra", rpm: "kernel-trace-extra~3.0.101~108.111.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-extra", rpm: "kernel-xen-extra~3.0.101~108.111.1", rls: "SLES11.0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigmem", rpm: "kernel-bigmem~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigmem-base", rpm: "kernel-bigmem-base~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-bigmem-devel", rpm: "kernel-bigmem-devel~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-base", rpm: "kernel-ec2-base~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae", rpm: "kernel-pae~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-base", rpm: "kernel-pae-base~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-devel", rpm: "kernel-pae-devel~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64", rpm: "kernel-ppc64~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-base", rpm: "kernel-ppc64-base~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ppc64-devel", rpm: "kernel-ppc64-devel~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace", rpm: "kernel-trace~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-base", rpm: "kernel-trace-base~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-trace-devel", rpm: "kernel-trace-devel~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.0.101~108.111.1", rls: "SLES11.0SP4" ) )){
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

