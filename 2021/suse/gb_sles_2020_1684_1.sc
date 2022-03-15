if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1684.1" );
	script_cve_id( "CVE-2019-2949", "CVE-2020-2654", "CVE-2020-2754", "CVE-2020-2755", "CVE-2020-2756", "CVE-2020-2757", "CVE-2020-2781", "CVE-2020-2800", "CVE-2020-2803", "CVE-2020-2805", "CVE-2020-2830" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1684-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1|SLES15\\.0SP2|SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1684-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201684-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_8_0-ibm' package(s) announced via the SUSE-SU-2020:1684-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_8_0-ibm fixes the following issues:

java-1_8_0-ibm was updated to Java 8.0 Service Refresh 6 Fix Pack 10
(bsc#1172277,bsc#1169511,bsc#1160968)

CVE-2020-2654: Fixed an issue which could have resulted in unauthorized
 ability to cause a partial denial of service

CVE-2020-2754: Forwarded references to Nashorn

CVE-2020-2755: Improved Nashorn matching

CVE-2020-2756: Improved mapping of serial ENUMs

CVE-2020-2757: Less Blocking Array Queues

CVE-2020-2781: Improved TLS session handling

CVE-2020-2800: Improved Headings for HTTP Servers

CVE-2020-2803: Enhanced buffering of byte buffers

CVE-2020-2805: Enhanced typing of methods

CVE-2020-2830: Improved Scanner conversions

CVE-2019-2949: Fixed an issue which could have resulted in unauthorized
 access to critical data

Added RSA PSS SUPPORT TO IBMPKCS11IMPL

The pack200 and unpack200 alternatives should be slaves of java
 (bsc#1171352)." );
	script_tag( name: "affected", value: "'java-1_8_0-ibm' package(s) on SUSE Linux Enterprise Module for Legacy Software 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm", rpm: "java-1_8_0-ibm~1.8.0_sr6.10~3.38.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-alsa", rpm: "java-1_8_0-ibm-alsa~1.8.0_sr6.10~3.38.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-devel", rpm: "java-1_8_0-ibm-devel~1.8.0_sr6.10~3.38.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-plugin", rpm: "java-1_8_0-ibm-plugin~1.8.0_sr6.10~3.38.1", rls: "SLES15.0SP1" ) )){
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm", rpm: "java-1_8_0-ibm~1.8.0_sr6.10~3.38.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-alsa", rpm: "java-1_8_0-ibm-alsa~1.8.0_sr6.10~3.38.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-devel", rpm: "java-1_8_0-ibm-devel~1.8.0_sr6.10~3.38.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-plugin", rpm: "java-1_8_0-ibm-plugin~1.8.0_sr6.10~3.38.1", rls: "SLES15.0SP2" ) )){
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm", rpm: "java-1_8_0-ibm~1.8.0_sr6.10~3.38.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-ibm-devel", rpm: "java-1_8_0-ibm-devel~1.8.0_sr6.10~3.38.1", rls: "SLES15.0" ) )){
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

