if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.3081.1" );
	script_cve_id( "CVE-2016-0762", "CVE-2016-5018", "CVE-2016-6794", "CVE-2016-6796", "CVE-2016-6797", "CVE-2016-6816", "CVE-2016-8735" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 22:15:00 +0000 (Mon, 05 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:3081-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:3081-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20163081-1/" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/tomcat-8.0-doc/RUNNING.txt" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat' package(s) announced via the SUSE-SU-2016:3081-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tomcat fixes the following issues:
Feature changes:
The embedded Apache Commons DBCP component was updated to version 2.0.
(bsc#1010893 fate#321029)
Security fixes:
- CVE-2016-0762: Realm Timing Attack (bsc#1007854)
- CVE-2016-5018: Security Manager Bypass (bsc#1007855)
- CVE-2016-6794: System Property Disclosure (bsc#1007857)
- CVE-2016-6796: Security Manager Bypass (bsc#1007858)
- CVE-2016-6797: Unrestricted Access to Global Resources (bsc#1007853)
- CVE-2016-8735: Remote code execution vulnerability in
 JmxRemoteLifecycleListener (bsc#1011805)
- CVE-2016-6816: HTTP Request smuggling vulnerability due to permitting
 invalid character in HTTP requests (bsc#1011812)
Bug fixes:
- Enabled optional setenv.sh script. See section '(3.4) Using the 'setenv'
 script' in [link moved to references].
 (bsc#1002639)" );
	script_tag( name: "affected", value: "'tomcat' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "tomcat", rpm: "tomcat~8.0.36~17.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-admin-webapps", rpm: "tomcat-admin-webapps~8.0.36~17.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-docs-webapp", rpm: "tomcat-docs-webapp~8.0.36~17.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-el-3_0-api", rpm: "tomcat-el-3_0-api~8.0.36~17.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-javadoc", rpm: "tomcat-javadoc~8.0.36~17.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsp-2_3-api", rpm: "tomcat-jsp-2_3-api~8.0.36~17.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-lib", rpm: "tomcat-lib~8.0.36~17.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-servlet-3_1-api", rpm: "tomcat-servlet-3_1-api~8.0.36~17.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-webapps", rpm: "tomcat-webapps~8.0.36~17.1", rls: "SLES12.0SP2" ) )){
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

