if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.3239.1" );
	script_cve_id( "CVE-2017-13672", "CVE-2017-15289", "CVE-2017-15592", "CVE-2017-15595", "CVE-2017-15597" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:3239-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:3239-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20173239-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:3239-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes several issues.
These security issues were fixed:
- bsc#1068187: Failure to recognize errors in the Populate on Demand (PoD)
 code allowed for DoS (XSA-246)
- bsc#1068191: Missing p2m error checking in PoD code allowed unprivileged
 guests to retain a writable mapping of freed memory leading to
 information leaks, privilege escalation or DoS (XSA-247).
- CVE-2017-15289: The mode4and5 write functions allowed local OS guest
 privileged users to cause a denial of service (out-of-bounds write
 access and Qemu process crash) via vectors related to dst calculation
 (bsc#1063123)
- CVE-2017-15597: A grant copy operation being done on a grant of a dying
 domain allowed a malicious guest administrator to corrupt hypervisor
 memory, allowing for DoS or potentially privilege escalation and
 information leaks (bsc#1061075).
- CVE-2017-15595: x86 PV guest OS users were able to cause a DoS
 (unbounded recursion, stack consumption, and hypervisor crash) or
 possibly gain privileges via crafted page-table stacking (bsc#1061081).
- CVE-2017-15592: x86 HVM guest OS users were able to cause a DoS
 (hypervisor crash) or possibly gain privileges because self-linear
 shadow mappings were mishandled for translated guests (bsc#1061086).
- CVE-2017-13672: The VGA display emulator support allowed local guest OS
 privileged users to cause a denial of service (out-of-bounds read and
 QEMU process crash) via vectors involving display update (bsc#1056336)
This non-security issue was fixed:
- bsc#1055047: Fixed --initrd-inject option in virt-install" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE Linux Enterprise Server 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.4.4_26~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.4.4_26~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.4.4_26~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.4.4_26_k3.12.61_52.101~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default-debuginfo", rpm: "xen-kmp-default-debuginfo~4.4.4_26_k3.12.61_52.101~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.4.4_26~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.4.4_26~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo-32bit", rpm: "xen-libs-debuginfo-32bit~4.4.4_26~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.4.4_26~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.4.4_26~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.4.4_26~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.4.4_26~22.59.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.4.4_26~22.59.3", rls: "SLES12.0" ) )){
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

