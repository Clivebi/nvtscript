if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0388.1" );
	script_cve_id( "CVE-2018-12207", "CVE-2018-19965", "CVE-2019-11135", "CVE-2019-12067", "CVE-2019-12068", "CVE-2019-12155", "CVE-2019-14378", "CVE-2019-15890", "CVE-2019-17340", "CVE-2019-17341", "CVE-2019-17342", "CVE-2019-17343", "CVE-2019-17344", "CVE-2019-17347", "CVE-2019-18420", "CVE-2019-18421", "CVE-2019-18424", "CVE-2019-18425", "CVE-2019-19577", "CVE-2019-19578", "CVE-2019-19579", "CVE-2019-19580", "CVE-2019-19581", "CVE-2019-19583", "CVE-2020-7211" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-14 16:15:00 +0000 (Thu, 14 Nov 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0388-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0388-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200388-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2020:0388-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes the following issues:
CVE-2018-12207: Fixed a race condition where untrusted virtual machines
 could have been using the Instruction Fetch Unit of the Intel CPU to
 cause a Machine Exception during Page Size Change, causing the CPU core
 to be non-functional (bsc#1155945 XSA-304).

CVE-2018-19965: Fixed a DoS from attempting to use INVPCID with a
 non-canonical addresses (bsc#1115045 XSA-279).

CVE-2019-11135: Aborting an asynchronous TSX operation on Intel CPUs
 with Transactional Memory support could be used to facilitate
 side-channel information leaks out of microarchitectural buffers,
 similar to the previously described 'Microarchitectural Data Sampling'
 attack. (bsc#1152497 XSA-305).

CVE-2019-12067: Fixed a null pointer dereference in QEMU AHCI
 (bsc#1145652).

CVE-2019-12068: Fixed an infinite loop while executing script
 (bsc#1146874).

CVE-2019-12155: Fixed a null pointer dereference while releasing spice
 resources (bsc#1135905).

CVE-2019-14378: Fixed a heap buffer overflow during packet reassembly in
 slirp networking implementation (bsc#1143797).

CVE-2019-15890: Fixed a use-after-free during packet reassembly
 (bsc#1149813).

CVE-2019-17340: Fixed grant table transfer issues on large hosts
 (XSA-284 bsc#1126140).

CVE-2019-17341: Fixed a race with pass-through device hotplug (XSA-285
 bsc#1126141).

CVE-2019-17342: Fixed steal_page violating page_struct access discipline
 (XSA-287 bsc#1126192).

CVE-2019-17343: Fixed an inconsistent PV IOMMU discipline (XSA-288
 bsc#1126195).

CVE-2019-17344: Fixed a missing preemption in x86 PV page table
 unvalidation (XSA-290 bsc#1126196).

CVE-2019-17347: Fixed a PV kernel context switch corruption (XSA-293
 bsc#1126201).

CVE-2019-18420: Fixed a hypervisor crash that could be caused by
 malicious x86 PV guests, resulting in a denial of service (bsc#1154448
 XSA-296).

CVE-2019-18421: Fixed a privilege escalation through malicious PV guest
 administrators (bsc#1154458 XSA-299).

CVE-2019-18424: Fixed a privilege escalation through DMA to physical
 devices by untrusted domains (bsc#1154461 XSA-302).

CVE-2019-18425: Fixed a privilege escalation from 32-bit PV guest used
 mode (bsc#1154456 XSA-298).

CVE-2019-19577: Fixed an issue where a malicious guest administrator
 could have caused Xen to access data structures while they are being
 modified leading to a crash (bsc#1158007 XSA-311).

CVE-2019-19578: Fixed an issue where a malicious or buggy PV guest could
 have caused hypervisor crash resulting in denial of service affecting
 the entire host (bsc#1158005 XSA-309).

CVE-2019-19579: Fixed a privilege escalation where an untrusted domain
 with access to a physical device can DMA into host memory (bsc#1157888
 XSA-306).

CVE-2019-19580: Fixed a privilege escalation where a malicious PV guest
 administrator could have been able to escalate their privilege to that
 of the host (bsc#1158006 ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.5.5_28~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.5.5_28~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.5.5_28~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.5.5_28_k3.12.74_60.64.124~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default-debuginfo", rpm: "xen-kmp-default-debuginfo~4.5.5_28_k3.12.74_60.64.124~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.5.5_28~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.5.5_28~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo-32bit", rpm: "xen-libs-debuginfo-32bit~4.5.5_28~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.5.5_28~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.5.5_28~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.5.5_28~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.5.5_28~22.64.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.5.5_28~22.64.1", rls: "SLES12.0SP1" ) )){
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

