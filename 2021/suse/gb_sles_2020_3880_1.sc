if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.3880.1" );
	script_cve_id( "CVE-2020-29130", "CVE-2020-29480", "CVE-2020-29481", "CVE-2020-29483", "CVE-2020-29484", "CVE-2020-29566", "CVE-2020-29570", "CVE-2020-29571", "CVE-2020-8608" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-16 13:13:00 +0000 (Tue, 16 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:3880-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:3880-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20203880-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2020:3880-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes the following issues:

CVE-2020-29480: Fixed an issue which could have allowed leak of
 non-sensitive data to administrator guests (bsc#117949 XSA-115).

CVE-2020-29481: Fixed an issue which could have allowd to new domains to
 inherit existing node permissions (bsc#1179498 XSA-322).

CVE-2020-29483: Fixed an issue where guests could disturb domain cleanup
 (bsc#1179502 XSA-325).

CVE-2020-29484: Fixed an issue where guests could crash xenstored via
 watchs (bsc#1179501 XSA-324).

CVE-2020-29566: Fixed an undue recursion in x86 HVM context switch code
 (bsc#1179506 XSA-348).

CVE-2020-29570: Fixed an issue where FIFO event channels control block
 related ordering (bsc#1179514 XSA-358).

CVE-2020-29571: Fixed an issue where FIFO event channels control
 structure ordering (bsc#1179516 XSA-359).

CVE-2020-29130: Fixed an out-of-bounds access while processing ARP
 packets (bsc#1179477).

Fixed an issue where dump-core shows missing nr_pages during core
 (bsc#1176782).

Multiple other bugs (bsc#1027519)" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.12.4_06~3.36.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.12.4_06~3.36.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.12.4_06~3.36.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.12.4_06~3.36.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.12.4_06~3.36.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo-32bit", rpm: "xen-libs-debuginfo-32bit~4.12.4_06~3.36.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.12.4_06~3.36.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.12.4_06~3.36.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.12.4_06~3.36.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.12.4_06~3.36.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.12.4_06~3.36.1", rls: "SLES12.0SP5" ) )){
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

