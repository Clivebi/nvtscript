if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.3043.1" );
	script_cve_id( "CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5556", "CVE-2016-5568", "CVE-2016-5573", "CVE-2016-5597" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:3043-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1|SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:3043-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20163043-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_1-ibm' package(s) announced via the SUSE-SU-2016:3043-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_7_1-ibm fixes the following issues:
- Version update to 7.1-3.60 (bsc#1009280) Fixing the following CVE's:
 CVE-2016-5568, CVE-2016-5556, CVE-2016-5573, CVE-2016-5597,
 CVE-2016-5554, CVE-2016-5542" );
	script_tag( name: "affected", value: "'java-1_7_1-ibm' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm", rpm: "java-1_7_1-ibm~1.7.1_sr3.60~31.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-alsa", rpm: "java-1_7_1-ibm-alsa~1.7.1_sr3.60~31.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-devel", rpm: "java-1_7_1-ibm-devel~1.7.1_sr3.60~31.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-jdbc", rpm: "java-1_7_1-ibm-jdbc~1.7.1_sr3.60~31.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-plugin", rpm: "java-1_7_1-ibm-plugin~1.7.1_sr3.60~31.2", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm", rpm: "java-1_7_1-ibm~1.7.1_sr3.60~31.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-alsa", rpm: "java-1_7_1-ibm-alsa~1.7.1_sr3.60~31.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-jdbc", rpm: "java-1_7_1-ibm-jdbc~1.7.1_sr3.60~31.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-plugin", rpm: "java-1_7_1-ibm-plugin~1.7.1_sr3.60~31.2", rls: "SLES12.0SP1" ) )){
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm", rpm: "java-1_7_1-ibm~1.7.1_sr3.60~31.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-alsa", rpm: "java-1_7_1-ibm-alsa~1.7.1_sr3.60~31.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-jdbc", rpm: "java-1_7_1-ibm-jdbc~1.7.1_sr3.60~31.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-plugin", rpm: "java-1_7_1-ibm-plugin~1.7.1_sr3.60~31.2", rls: "SLES12.0SP2" ) )){
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
