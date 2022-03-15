if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0580.1" );
	script_cve_id( "CVE-2019-14615", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-16994", "CVE-2019-18808", "CVE-2019-19036", "CVE-2019-19045", "CVE-2019-19054", "CVE-2019-19318", "CVE-2019-19319", "CVE-2019-19447", "CVE-2019-19767", "CVE-2019-19927", "CVE-2019-19965", "CVE-2019-19966", "CVE-2019-20054", "CVE-2019-20095", "CVE-2019-20096", "CVE-2020-7053", "CVE-2020-8428", "CVE-2020-8648", "CVE-2020-8992" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-03 11:15:00 +0000 (Fri, 03 Jan 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0580-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0580-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200580-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:0580-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-14615: An information disclosure vulnerability existed due to
 insufficient control flow in certain data structures for some Intel(R)
 Processors (bnc#1160195).

CVE-2019-14896: A heap-based buffer overflow vulnerability was found in
 the Marvell WiFi driver. A remote attacker could cause a denial of
 service (system crash) or, possibly execute arbitrary code, when the
 lbs_ibss_join_existing function is called after a STA connects to an AP
 (bnc#1157157).

CVE-2019-14897: A stack-based buffer overflow was found in the Marvell
 WiFi driver. An attacker is able to cause a denial of service (system
 crash) or, possibly execute arbitrary code, when a STA works in IBSS
 mode (allows connecting stations together without the use of an AP) and
 connects to another STA (bnc#1157155).

CVE-2019-16994: A memory leak existed in sit_init_net() in
 net/ipv6/sit.c which might have caused denial of service, aka
 CID-07f12b26e21a (bnc#1161523).

CVE-2019-18808: A memory leak in drivers/crypto/ccp/ccp-ops.c allowed
 attackers to cause a denial of service (memory consumption), aka
 CID-128c66429247 (bnc#1156259).

CVE-2019-19036: An issue discovered in btrfs_root_node in
 fs/btrfs/ctree.c allowed a NULL pointer dereference because
 rcu_dereference(root->node) can be zero (bnc#1157692).

CVE-2019-19045: A memory leak in
 drivers/net/ethernet/mellanox/mlx5/core/fpga/conn.c allowed attackers to
 cause a denial of service (memory consumption) by triggering
 mlx5_vector2eqn() failures, aka CID-c8c2a057fdc7 (bnc#1161522).

CVE-2019-19054: A memory leak in the cx23888_ir_probe() function in
 drivers/media/pci/cx23885/cx23888-ir.c allowed attackers to cause a
 denial of service (memory consumption) by triggering kfifo_alloc()
 failures, aka CID-a7b2df76b42b (bnc#1161518).

CVE-2019-19318: Mounting a crafted btrfs image twice could have caused a
 use-after-free (bnc#1158026).

CVE-2019-19319: A slab-out-of-bounds write access could have occured
 when setxattr was called after mounting of a specially crafted ext4
 image (bnc#1158021).

CVE-2019-19447: Mounting a crafted ext4 filesystem image, performing
 some operations, and unmounting could have led to a use-after-free in
 fs/ext4/super.c (bnc#1158819).

CVE-2019-19767: There were multiple use-after-free errors in
 __ext4_expand_extra_isize and ext4_xattr_set_entry, related to
 fs/ext4/inode.c and fs/ext4/super.c, aka CID-4ea99936a163 (bnc#1159297).

CVE-2019-19927: A slab-out-of-bounds read access occured when mounting a
 crafted f2fs filesystem image and performing some operations on it
 (bnc#1160147).

CVE-2019-19965: There was a NULL pointer dereference in
 drivers/scsi/libsas/sas_discover.c because of mishandling of port
 disconnection during discovery, related to a PHY down race condition,
 aka ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP5, SUSE Linux Enterprise Live Patching 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5." );
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.12.14~122.17.1", rls: "SLES12.0SP5" ) )){
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

