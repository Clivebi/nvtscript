if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.3379.1" );
	script_cve_id( "CVE-2019-14895", "CVE-2019-15213", "CVE-2019-16231", "CVE-2019-18660", "CVE-2019-18680", "CVE-2019-18683", "CVE-2019-18805", "CVE-2019-19052", "CVE-2019-19062", "CVE-2019-19065", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19332", "CVE-2019-19338", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19527", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19535", "CVE-2019-19536", "CVE-2019-19537" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-12 16:15:00 +0000 (Thu, 12 Dec 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:3379-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:3379-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20193379-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:3379-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP 3 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-14895: A heap-based buffer overflow was discovered in the Linux
 kernel in Marvell WiFi chip driver. The flaw could occur when the
 station attempts a connection negotiation during the handling of the
 remote devices country settings. This could have allowed the remote
 device to cause a denial of service (system crash) or possibly execute
 arbitrary code (bnc#1157158).

CVE-2019-18660: The Linux kernel on powerpc allowed Information Exposure
 because the Spectre-RSB mitigation is not in place for all applicable
 CPUs. This is related to arch/powerpc/kernel/entry_64.S and
 arch/powerpc/kernel/security.c (bnc#1157038).

CVE-2019-18683: An issue was discovered in drivers/media/platform/vivid
 in the Linux kernel. It is exploitable for privilege escalation on some
 Linux distributions where local users have /dev/video0 access, but only
 if the driver happens to be loaded. There are multiple race conditions
 during streaming stopping in this driver (part of the V4L2 subsystem).
 These issues are caused by wrong mutex locking in
 vivid_stop_generating_vid_cap(), vivid_stop_generating_vid_out(),
 sdr_cap_stop_streaming(), and the corresponding kthreads. At least one
 of these race conditions leads to a use-after-free (bnc#1155897).

CVE-2019-19062: A memory leak in the crypto_report() function in
 crypto/crypto_user_base.c in the Linux kernel allowed attackers to cause
 a denial of service (memory consumption) by triggering
 crypto_report_alg() failures (bnc#1157333).

CVE-2019-19065: A memory leak in the sdma_init() function in
 drivers/infiniband/hw/hfi1/sdma.c in the Linux kernel allowed attackers
 to cause a denial of service (memory consumption) by triggering
 rhashtable_init() failures (bnc#1157191).

CVE-2019-19052: A memory leak in the gs_can_open() function in
 drivers/net/can/usb/gs_usb.c in the Linux kernel allowed attackers to
 cause a denial of service (memory consumption) by triggering
 usb_submit_urb() failures (bnc#1157324).

CVE-2019-19074: A memory leak in the ath9k_wmi_cmd() function in
 drivers/net/wireless/ath/ath9k/wmi.c in the Linux kernel allowed
 attackers to cause a denial of service (memory consumption)
 (bnc#1157143).

CVE-2019-19073: Memory leaks in drivers/net/wireless/ath/ath9k/htc_hst.c
 in the Linux kernel allowed attackers to cause a denial of service
 (memory consumption) by triggering wait_for_completion_timeout()
 failures. This affects the htc_config_pipe_credits() function, the
 htc_setup_complete() function, and the htc_connect_service() function
 (bnc#1157070).

CVE-2019-16231: drivers/net/fjes/fjes_main.c in the Linux kernel 5.2.14
 did not check the alloc_workqueue return value, leading to a NULL
 pointer dereference (bnc#1150466).

CVE-2019-18805: An issue was discovered in ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on HPE Helion Openstack 8, SUSE CaaS Platform 3.0, SUSE Enterprise Storage 5, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-kgraft", rpm: "kernel-default-kgraft~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.180~94.113.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_113-default", rpm: "kgraft-patch-4_4_180-94_113-default~1~4.5.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_113-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_113-default-debuginfo~1~4.5.1", rls: "SLES12.0SP3" ) )){
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

