if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.3049.1" );
	script_cve_id( "CVE-2020-27670", "CVE-2020-27671", "CVE-2020-27672", "CVE-2020-27673" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:51 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-19 20:15:00 +0000 (Tue, 19 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:3049-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:3049-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20203049-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2020:3049-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes the following issues:

bsc#1177409 - VUL-0: CVE-2020-27673: xen: x86 PV guest INVLPG-like
 flushes may leave stale TLB entries (XSA-286)

bsc#1177412 - VUL-0: CVE-2020-27672: xen: Race condition in Xen mapping
 code (XSA-345)

bsc#1177413 - VUL-0: CVE-2020-27671: xen: undue deferral of IOMMU TLB
 flushes (XSA-346)

bsc#1177414 - VUL-0: CVE-2020-27670: xen: unsafe AMD IOMMU page table
 updates (XSA-347)" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Server Applications 15-SP2." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.13.1_10~3.13.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.13.1_10~3.13.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.13.1_10~3.13.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.13.1_10~3.13.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.13.1_10~3.13.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.13.1_10~3.13.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~4.13.1_10~3.13.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.13.1_10~3.13.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.13.1_10~3.13.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-xendomains-wait-disk", rpm: "xen-tools-xendomains-wait-disk~4.13.1_10~3.13.1", rls: "SLES15.0SP2" ) )){
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

