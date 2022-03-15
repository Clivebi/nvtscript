if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.14521.1" );
	script_cve_id( "CVE-2020-0543", "CVE-2020-14364", "CVE-2020-15565", "CVE-2020-15567", "CVE-2020-25595", "CVE-2020-25596", "CVE-2020-25597", "CVE-2020-25600", "CVE-2020-25601", "CVE-2020-25603", "CVE-2020-25604" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:51 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:14521-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:14521-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-202014521-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2020:14521-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes the following issues:

CVE-2020-0543: Fixed a leak of Special Register Buffer Data Sampling
 (SRBDS) aka 'CrossTalk' (bsc#1172205,XSA-320)

CVE-2020-14364: Fixed an out-of-bounds read/write access while
 processing usb packets (bsc#1175534).

CVE-2020-15565: Fixed an issue cache write (bsc#1173378,XSA-321).

CVE-2020-15567: Fixed an issue with non-atomic modification of live EPT
 PTE (bsc#1173380,XSA-328)

CVE-2020-25595: Fixed an issue where PCI passthrough code was reading
 back hardware registers (bsc#1176344,XSA-337)

CVE-2020-25596: Fixed a potential denial of service in x86 pv guest
 kernel via SYSENTER (bsc#1176345,XSA-339)

CVE-2020-25597: Fixed an issue where a valid event channels may not turn
 invalid (bsc#1176346,XSA-338)

CVE-2020-25600: Fixed out of bounds event channels available to 32-bit
 x86 domains (bsc#1176348,XSA-342)

CVE-2020-25601: Fixed an issue due to lack of preemption in
 evtchn_reset() / evtchn_destroy() (bsc#1176350,XSA-344)

CVE-2020-25603: Fixed an issue due to missing barriers when
 accessing/allocating an event channel (bsc#1176347,XSA-340)

CVE-2020-25604: Fixed a race condition when migrating timers between x86
 HVM vCPU-s (bsc#1176343,XSA-336)" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.4.4_44~61.55.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.4.4_44~61.55.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.4.4_44_3.0.101_108.117~61.55.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-pae", rpm: "xen-kmp-pae~4.4.4_44_3.0.101_108.117~61.55.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.4.4_44~61.55.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.4.4_44~61.55.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.4.4_44~61.55.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.4.4_44~61.55.1", rls: "SLES11.0SP4" ) )){
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

