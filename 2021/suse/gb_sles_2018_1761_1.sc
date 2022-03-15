if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1761.1" );
	script_cve_id( "CVE-2017-13305", "CVE-2018-1000204", "CVE-2018-1092", "CVE-2018-1093", "CVE-2018-1094", "CVE-2018-1130", "CVE-2018-3665", "CVE-2018-5803", "CVE-2018-5848", "CVE-2018-7492" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-02 15:54:00 +0000 (Thu, 02 May 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1761-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1761-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181761-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1761-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP1 LTSS kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2018-3665: Prevent disclosure of FPU registers (including XMM and
 AVX registers) between processes. These registers might contain
 encryption keys when doing SSE accelerated AES enc/decryption
 (bsc#1087086)
- CVE-2018-5848: In the function wmi_set_ie(), the length validation code
 did not handle unsigned integer overflow properly. As a result, a large
 value of the 'ie_len' argument could have caused a buffer overflow
 (bnc#1097356)
- CVE-2018-1000204: Prevent infoleak caused by incorrect handling of the
 SG_IO ioctl (bsc#1096728)
- CVE-2017-13305: Prevent information disclosure vulnerability in
 encrypted-keys (bsc#1094353)
- CVE-2018-1094: The ext4_fill_super function did not always initialize
 the crc32c checksum driver, which allowed attackers to cause a denial of
 service (ext4_xattr_inode_hash NULL pointer dereference and system
 crash) via a crafted ext4 image (bsc#1087007).
- CVE-2018-1093: The ext4_valid_block_bitmap function allowed attackers to
 cause a denial of service (out-of-bounds read and system crash) via a
 crafted ext4 image because balloc.c and ialloc.c do not validate bitmap
 block numbers (bsc#1087095).
- CVE-2018-1092: The ext4_iget function mishandled the case of a root
 directory with a zero i_links_count, which allowed attackers to cause a
 denial of service (ext4_process_freed_data NULL pointer dereference and
 OOPS) via a crafted ext4 image (bsc#1087012).
- CVE-2018-1130: NULL pointer dereference in dccp_write_xmit() function
 that allowed a local user to cause a denial of service by a number of
 certain crafted system calls (bsc#1092904)
- CVE-2018-5803: Prevent error in the '_sctp_make_chunk()' function when
 handling SCTP packets length that could have been exploited to cause a
 kernel crash (bnc#1083900)
- CVE-2018-7492: Prevent NULL pointer dereference in the net/rds/rdma.c
 __rds_rdma_map() function that allowed local attackers to cause a system
 panic and a denial-of-service, related to RDS_GET_MR and
 RDS_GET_MR_FOR_DEST (bsc#1082962)
The following non-security bugs were fixed:
- Btrfs: fix unexpected balance crash due to BUG_ON (bsc#1038553).
- Fix excessive newline in /proc/*/status (bsc#1094823).
- KVM: x86: Sync back MSR_IA32_SPEC_CTRL to VCPU data structure
 (bsc#1096242, bsc#1096281).
- dm thin metadata: call precommit before saving the roots (bsc#1083382).
- dm thin: fix inability to discard blocks when in out-of-data-space mode
 (bsc#1083382).
- dm thin: fix missing out-of-data-space to write mode transition if
 blocks are released (bsc#1083382).
- dm thin: restore requested 'error_if_no_space' setting on OODS to WRITE
 transition (bsc#1083382).
- dm: fix various targets to dm_register_target after module __init
 resources created (bsc#1083382).
- kABI: work around BPF SSBD removal ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.12.74~60.64.96.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debuginfo", rpm: "kernel-ec2-debuginfo~3.12.74~60.64.96.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debugsource", rpm: "kernel-ec2-debugsource~3.12.74~60.64.96.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.12.74~60.64.96.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra", rpm: "kernel-ec2-extra~3.12.74~60.64.96.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra-debuginfo", rpm: "kernel-ec2-extra-debuginfo~3.12.74~60.64.96.1", rls: "SLES12.0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base-debuginfo", rpm: "kernel-xen-base-debuginfo~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.12.74~60.64.96.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_74-60_64_96-default", rpm: "kgraft-patch-3_12_74-60_64_96-default~1~2.3.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_74-60_64_96-xen", rpm: "kgraft-patch-3_12_74-60_64_96-xen~1~2.3.1", rls: "SLES12.0SP1" ) )){
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

