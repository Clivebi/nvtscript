if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.3200.1" );
	script_cve_id( "CVE-2017-18595", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-10220", "CVE-2019-11135", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-14895", "CVE-2019-15030", "CVE-2019-15031", "CVE-2019-15916", "CVE-2019-16231", "CVE-2019-16233", "CVE-2019-16995", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17666", "CVE-2019-18660", "CVE-2019-18683", "CVE-2019-18805", "CVE-2019-18809", "CVE-2019-19046", "CVE-2019-19049", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19060", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19078", "CVE-2019-19080", "CVE-2019-19081", "CVE-2019-19082", "CVE-2019-19083", "CVE-2019-19227", "CVE-2019-9456", "CVE-2019-9506" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-12 16:15:00 +0000 (Thu, 12 Dec 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:3200-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:3200-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20193200-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:3200-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-19081: Fixed a memory leak in the nfp_flower_spawn_vnic_reprs()
 could have allowed attackers to cause a denial of service (bsc#1157045).

CVE-2019-19080: Fixed four memory leaks in the
 nfp_flower_spawn_phy_reprs() could have allowed attackers to cause a
 denial of service (bsc#1157044).

CVE-2019-19052: Fixed a memory leak in the gs_can_open() which could
 have led to denial of service (bsc#1157324).

CVE-2019-19067: Fixed multiple memory leaks in acp_hw_init (bsc#1157180).

CVE-2019-19060: Fixed a memory leak in the adis_update_scan_mode() which
 could have led to denial of service (bsc#1157178).

CVE-2019-19049: Fixed a memory leak in unittest_data_add (bsc#1157173).

CVE-2019-19075: Fixed a memory leak in the ca8210_probe() which could
 have led to denial of service by triggering ca8210_get_platform_data()
 failures (bsc#1157162).

CVE-2019-19058: Fixed a memory leak in the alloc_sgtable() which could
 have led to denial of service by triggering alloc_page() failures
 (bsc#1157145).

CVE-2019-19074: Fixed a memory leak in the ath9k_wmi_cmd() function
 which could have led to denial of service (bsc#1157143).

CVE-2019-19073: Fixed multiple memory leaks in
 drivers/net/wireless/ath/ath9k/htc_hst.c which could have led to denial
 of service by triggering wait_for_completion_timeout() failures
 (bsc#1157070).

CVE-2019-19083: Fixed multiple memory leaks in *clock_source_create()
 functions which could have led to denial of service (bsc#1157049).

CVE-2019-19082: Fixed multiple memory leaks in *create_resource_pool()
 which could have led to denial of service (bsc#1157046).

CVE-2019-15916: Fixed a memory leak in register_queue_kobjects() which
 might have led denial of service (bsc#1149448).

CVE-2019-0154: Fixed an improper access control in subsystem for Intel
 (R) processor graphics whichs may have allowed an authenticated user to
 potentially enable denial of service via local access (bsc#1135966).

CVE-2019-0155: Fixed an improper access control in subsystem for Intel
 (R) processor graphics whichs may have allowed an authenticated user to
 potentially enable escalation of privilege via local access
 (bsc#1135967).

CVE-2019-16231: Fixed a NULL pointer dereference due to lack of checking
 the alloc_workqueue return value (bsc#1150466).

CVE-2019-18805: Fixed an integer overflow in tcp_ack_update_rtt()
 leading to a denial of service or possibly unspecified other impact
 (bsc#1156187).

CVE-2019-17055: Enforced CAP_NET_RAW in the AF_ISDN network module to
 restrict unprivileged users to create a raw socket (bsc#1152782).

CVE-2019-16995: Fixed a memory leak in hsr_dev_finalize() which may have
 caused denial of service (bsc#1152685).

CVE-2019-16233: drivers/scsi/qla2xxx/qla_os.c did not check the
 alloc_workqueue return ... [Please see the references for more information on the vulnerabilities]" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.12.14~122.7.1", rls: "SLES12.0SP5" ) )){
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

