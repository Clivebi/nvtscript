if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0663.1" );
	script_cve_id( "CVE-2018-2579", "CVE-2018-2582", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2629", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2641", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0663-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1|SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0663-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180663-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_8_0-openjdk' package(s) announced via the SUSE-SU-2018:0663-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_8_0-openjdk fixes the following issues:
Security issues fix in jdk8u161 (icedtea 3.7.0)(bsc#1076366):
- CVE-2018-2579: Improve key keying case
- CVE-2018-2582: Better interface invocations
- CVE-2018-2588: Improve LDAP logins
- CVE-2018-2599: Improve reliability of DNS lookups
- CVE-2018-2602: Improve usage messages
- CVE-2018-2603: Improve PKCS usage
- CVE-2018-2618: Stricter key generation
- CVE-2018-2629: Improve GSS handling
- CVE-2018-2633: Improve LDAP lookup robustness
- CVE-2018-2634: Improve property negotiations
- CVE-2018-2637: Improve JMX supportive features
- CVE-2018-2641: Improve GTK initialization
- CVE-2018-2663: More refactoring for deserialization cases
- CVE-2018-2677: More refactoring for client deserialization cases
- CVE-2018-2678: More refactoring for naming deserialization cases" );
	script_tag( name: "affected", value: "'java-1_8_0-openjdk' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE OpenStack Cloud 6." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk", rpm: "java-1_8_0-openjdk~1.8.0.161~27.13.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debuginfo", rpm: "java-1_8_0-openjdk-debuginfo~1.8.0.161~27.13.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debugsource", rpm: "java-1_8_0-openjdk-debugsource~1.8.0.161~27.13.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo", rpm: "java-1_8_0-openjdk-demo~1.8.0.161~27.13.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo-debuginfo", rpm: "java-1_8_0-openjdk-demo-debuginfo~1.8.0.161~27.13.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-devel", rpm: "java-1_8_0-openjdk-devel~1.8.0.161~27.13.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless", rpm: "java-1_8_0-openjdk-headless~1.8.0.161~27.13.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless-debuginfo", rpm: "java-1_8_0-openjdk-headless-debuginfo~1.8.0.161~27.13.1", rls: "SLES12.0SP1" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk", rpm: "java-1_8_0-openjdk~1.8.0.161~27.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debuginfo", rpm: "java-1_8_0-openjdk-debuginfo~1.8.0.161~27.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debugsource", rpm: "java-1_8_0-openjdk-debugsource~1.8.0.161~27.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo", rpm: "java-1_8_0-openjdk-demo~1.8.0.161~27.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo-debuginfo", rpm: "java-1_8_0-openjdk-demo-debuginfo~1.8.0.161~27.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-devel", rpm: "java-1_8_0-openjdk-devel~1.8.0.161~27.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-devel-debuginfo", rpm: "java-1_8_0-openjdk-devel-debuginfo~1.8.0.161~27.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless", rpm: "java-1_8_0-openjdk-headless~1.8.0.161~27.13.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless-debuginfo", rpm: "java-1_8_0-openjdk-headless-debuginfo~1.8.0.161~27.13.1", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk", rpm: "java-1_8_0-openjdk~1.8.0.161~27.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debuginfo", rpm: "java-1_8_0-openjdk-debuginfo~1.8.0.161~27.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debugsource", rpm: "java-1_8_0-openjdk-debugsource~1.8.0.161~27.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo", rpm: "java-1_8_0-openjdk-demo~1.8.0.161~27.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo-debuginfo", rpm: "java-1_8_0-openjdk-demo-debuginfo~1.8.0.161~27.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-devel", rpm: "java-1_8_0-openjdk-devel~1.8.0.161~27.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-devel-debuginfo", rpm: "java-1_8_0-openjdk-devel-debuginfo~1.8.0.161~27.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless", rpm: "java-1_8_0-openjdk-headless~1.8.0.161~27.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless-debuginfo", rpm: "java-1_8_0-openjdk-headless-debuginfo~1.8.0.161~27.13.1", rls: "SLES12.0SP3" ) )){
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

