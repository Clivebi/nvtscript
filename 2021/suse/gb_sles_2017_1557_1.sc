if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1557.1" );
	script_cve_id( "CVE-2016-9318", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:55 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1557-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3|SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1557-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171557-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2017:1557-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libxml2 fixes the following issues:
Security issues fixed:
- CVE-2017-9050: heap-based buffer overflow (xmlDictAddString func)
 [bsc#1039069, bsc#1039661]
- CVE-2017-9049: heap-based buffer overflow (xmlDictComputeFastKey func)
 [bsc#1039066]
- CVE-2017-9048: stack overflow vulnerability (xmlSnprintfElementContent
 func) [bsc#1039063]
- CVE-2017-9047: stack overflow vulnerability (xmlSnprintfElementContent
 func) [bsc#1039064]
A clarification for the previously released update: For CVE-2016-9318 we decided not to ship a fix since it can break existing setups. Please take appropriate actions if you parse untrusted XML files and use the new
-noxxe flag if possible (bnc#1010675, bnc#1013930)." );
	script_tag( name: "affected", value: "'libxml2' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.7.6~0.69.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-32bit", rpm: "libxml2-32bit~2.7.6~0.69.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-doc", rpm: "libxml2-doc~2.7.6~0.69.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-python", rpm: "libxml2-python~2.7.6~0.69.3", rls: "SLES11.0SP3" ) )){
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.7.6~0.69.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-32bit", rpm: "libxml2-32bit~2.7.6~0.69.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-doc", rpm: "libxml2-doc~2.7.6~0.69.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-python", rpm: "libxml2-python~2.7.6~0.69.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libxml2-x86", rpm: "libxml2-x86~2.7.6~0.69.1", rls: "SLES11.0SP4" ) )){
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

