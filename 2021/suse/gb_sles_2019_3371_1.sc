if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.3371.1" );
	script_cve_id( "CVE-2019-14895", "CVE-2019-15916", "CVE-2019-16231", "CVE-2019-17055", "CVE-2019-18660", "CVE-2019-18683", "CVE-2019-18805", "CVE-2019-18809", "CVE-2019-19049", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19060", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19077", "CVE-2019-19227" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-12 16:15:00 +0000 (Thu, 12 Dec 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:3371-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:3371-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20193371-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:3371-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

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

CVE-2019-18809: A memory leak in the af9005_identify_state() function in
 drivers/media/usb/dvb-usb/af9005.c in the Linux kernel allowed attackers
 to cause a denial of service (memory consumption) (bnc#1156258).

CVE-2019-19062: A memory leak in the crypto_report() function in
 crypto/crypto_user_base.c in the Linux kernel allowed attackers to cause
 a denial of service (memory consumption) by triggering
 crypto_report_alg() failures (bnc#1157333).

CVE-2019-19057: Two memory leaks in the mwifiex_pcie_init_evt_ring()
 function in drivers/net/wireless/marvell/mwifiex/pcie.c in the Linux
 kernel allowed attackers to cause a denial of service (memory
 consumption) by triggering mwifiex_map_pci_memory() failures
 (bnc#1157197).

CVE-2019-19056: A memory leak in the mwifiex_pcie_alloc_cmdrsp_buf()
 function in drivers/net/wireless/marvell/mwifiex/pcie.c in the Linux
 kernel allowed attackers to cause a denial of service (memory
 consumption) by triggering mwifiex_map_pci_memory() failures
 (bnc#1157197).

CVE-2019-19068: A memory leak in the rtl8xxxu_submit_int_urb() function
 in drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu_core.c in the Linux
 kernel allowed attackers to cause a denial of service (memory
 consumption) by triggering usb_submit_urb() failures (bnc#1157307).

CVE-2019-19063: Two memory leaks in the rtl_usb_probe() function in
 drivers/net/wireless/realtek/rtlwifi/usb.c in the Linux kernel allowed
 attackers to cause a denial of service (memory consumption)
 (bnc#1157298).

CVE-2019-19227: In ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise High Availability 12-SP4, SUSE Linux Enterprise Live Patching 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Workstation Extension 12-SP4." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.12.14~95.45.1", rls: "SLES12.0SP4" ) )){
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

