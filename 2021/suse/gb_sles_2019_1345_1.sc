if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1345.1" );
	script_cve_id( "CVE-2019-10245", "CVE-2019-2602", "CVE-2019-2684", "CVE-2019-2697", "CVE-2019-2698" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1345-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1|SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1345-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191345-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_1-ibm' package(s) announced via the SUSE-SU-2019:1345-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_7_1-ibm fixes the following issues:

Update to Java 7.1 Service Refresh 4 Fix Pack 45.

Security issues fixed:
CVE-2019-10245: Fixed Java bytecode verifier issue causing crashes
 (bsc#1134718).

CVE-2019-2698: Fixed out of bounds access flaw in the 2D component
 (bsc#1132729).

CVE-2019-2697: Fixed flaw inside the 2D component (bsc#1132734).

CVE-2019-2602: Fixed flaw inside BigDecimal implementation (Component:
 Libraries) (bsc#1132728).

CVE-2019-2684: Fixed flaw was found in the RMI registry implementation
 (bsc#1132732)." );
	script_tag( name: "affected", value: "'java-1_7_1-ibm' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE OpenStack Cloud 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm", rpm: "java-1_7_1-ibm~1.7.1_sr4.45~38.37.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-alsa", rpm: "java-1_7_1-ibm-alsa~1.7.1_sr4.45~38.37.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-devel", rpm: "java-1_7_1-ibm-devel~1.7.1_sr4.45~38.37.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-jdbc", rpm: "java-1_7_1-ibm-jdbc~1.7.1_sr4.45~38.37.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-plugin", rpm: "java-1_7_1-ibm-plugin~1.7.1_sr4.45~38.37.1", rls: "SLES12.0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm", rpm: "java-1_7_1-ibm~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-alsa", rpm: "java-1_7_1-ibm-alsa~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-devel", rpm: "java-1_7_1-ibm-devel~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-jdbc", rpm: "java-1_7_1-ibm-jdbc~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-plugin", rpm: "java-1_7_1-ibm-plugin~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP1" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm", rpm: "java-1_7_1-ibm~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-alsa", rpm: "java-1_7_1-ibm-alsa~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-devel", rpm: "java-1_7_1-ibm-devel~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-jdbc", rpm: "java-1_7_1-ibm-jdbc~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-plugin", rpm: "java-1_7_1-ibm-plugin~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm", rpm: "java-1_7_1-ibm~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-alsa", rpm: "java-1_7_1-ibm-alsa~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-jdbc", rpm: "java-1_7_1-ibm-jdbc~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-plugin", rpm: "java-1_7_1-ibm-plugin~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm", rpm: "java-1_7_1-ibm~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-alsa", rpm: "java-1_7_1-ibm-alsa~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-jdbc", rpm: "java-1_7_1-ibm-jdbc~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_1-ibm-plugin", rpm: "java-1_7_1-ibm-plugin~1.7.1_sr4.45~38.37.1", rls: "SLES12.0SP4" ) )){
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

