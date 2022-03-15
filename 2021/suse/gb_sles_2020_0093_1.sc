if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0093.1" );
	script_cve_id( "CVE-2017-18595", "CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-10220", "CVE-2019-11135", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-14895", "CVE-2019-14901", "CVE-2019-15030", "CVE-2019-15031", "CVE-2019-15213", "CVE-2019-15916", "CVE-2019-16231", "CVE-2019-16232", "CVE-2019-16233", "CVE-2019-16234", "CVE-2019-16746", "CVE-2019-16995", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-18660", "CVE-2019-18683", "CVE-2019-18805", "CVE-2019-18808", "CVE-2019-18809", "CVE-2019-19046", "CVE-2019-19049", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19060", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19066", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19077", "CVE-2019-19078", "CVE-2019-19080", "CVE-2019-19081", "CVE-2019-19082", "CVE-2019-19083", "CVE-2019-19227", "CVE-2019-19319", "CVE-2019-19332", "CVE-2019-19338", "CVE-2019-19447", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19526", "CVE-2019-19527", "CVE-2019-19528", "CVE-2019-19529", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19535", "CVE-2019-19536", "CVE-2019-19537", "CVE-2019-19543", "CVE-2019-19767", "CVE-2019-19966", "CVE-2019-20054", "CVE-2019-20095", "CVE-2019-20096", "CVE-2019-9456", "CVE-2019-9506" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-12 16:15:00 +0000 (Thu, 12 Dec 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0093-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0093-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200093-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:0093-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-20095: mwifiex_tm_cmd in
 drivers/net/wireless/marvell/mwifiex/cfg80211.c had some error-handling
 cases that did not free allocated hostcmd memory. This will cause a
 memory leak and denial of service (bnc#1159909).

CVE-2019-20054: Fixed a NULL pointer dereference in
 drop_sysctl_table() in fs/proc/proc_sysctl.c, related to put_links
 (bnc#1159910).

CVE-2019-20096: Fixed a memory leak in __feat_register_sp() in
 net/dccp/feat.c, which may cause denial of service (bnc#1159908).

CVE-2019-19966: Fixed a use-after-free in cpia2_exit() in
 drivers/media/usb/cpia2/cpia2_v4l.c that will cause denial of service
 (bnc#1159841).

CVE-2019-19447: Mounting a crafted ext4 filesystem image, performing
 some operations, and unmounting can lead to a use-after-free in
 ext4_put_super in fs/ext4/super.c, related to dump_orphan_list in
 fs/ext4/super.c (bnc#1158819).

CVE-2019-19319: A setxattr operation, after a mount of a crafted ext4
 image, can cause a slab-out-of-bounds write access because of an
 ext4_xattr_set_entry use-after-free in fs/ext4/xattr.c when a large
 old_size value is used in a memset call (bnc#1158021).

CVE-2019-19767: Fixed mishandling of ext4_expand_extra_isize, as
 demonstrated by use-after-free errors in __ext4_expand_extra_isize and
 ext4_xattr_set_entry, related to fs/ext4/inode.c and fs/ext4/super.c
 (bnc#1159297).

CVE-2019-18808: A memory leak in the ccp_run_sha_cmd() function in
 drivers/crypto/ccp/ccp-ops.c allowed attackers to cause a denial of
 service (memory consumption) (bnc#1156259).

CVE-2019-16746: An issue was discovered in net/wireless/nl80211.c where
 the length of variable elements in a beacon head were not checked,
 leading to a buffer overflow (bnc#1152107).

CVE-2019-19066: A memory leak in the bfad_im_get_stats() function in
 drivers/scsi/bfa/bfad_attr.c allowed attackers to cause a denial of
 service (memory consumption) by triggering bfa_port_get_stats() failures
 (bnc#1157303).

CVE-2019-19051: There was a memory leak in the
 i2400m_op_rfkill_sw_toggle() function in
 drivers/net/wimax/i2400m/op-rfkill.c in the Linux kernel allowed
 attackers to cause a denial of service (memory consumption)
 (bnc#1159024).

CVE-2019-19338: There was an incomplete fix for Transaction Asynchronous
 Abort (TAA) (bnc#1158954).

CVE-2019-19332: There was an OOB memory write via
 kvm_dev_ioctl_get_cpuid (bnc#1158827).

CVE-2019-19537: There was a race condition bug that can be caused by a
 malicious USB device in the USB character device driver layer
 (bnc#1158904).

CVE-2019-19535: There was an info-leak bug that can be caused by a
 malicious USB device in the drivers/net/can/usb/peak_usb/pcan_usb_fd.c
 driver (bnc#1158903).

CVE-2019-19527: There was a use-after-free bug that can be caused by a
 malicious ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.12.14~16.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.12.14~16.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.12.14~16.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.12.14~16.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.12.14~16.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.12.14~16.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.12.14~16.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.12.14~16.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.12.14~16.7.1", rls: "SLES12.0SP5" ) )){
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

