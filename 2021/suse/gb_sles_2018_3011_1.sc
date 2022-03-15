if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3011.1" );
	script_cve_id( "CVE-2018-1336", "CVE-2018-8014", "CVE-2018-8034", "CVE-2018-8037" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:36 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3011-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3011-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183011-1/" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/tomcat-9.0-doc/changelog.html#Tomcat_9.0.10_" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat' package(s) announced via the SUSE-SU-2018:3011-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tomcat to version 9.0.10 fixes the following issues:

Security issues fixed:
CVE-2018-1336: An improper handing of overflow in the UTF-8 decoder with
 supplementary characters could have lead to an infinite loop in the
 decoder causing a Denial of Service (bsc#1102400).

CVE-2018-8014: Fix insecure default CORS filter settings (bsc#1093697).

CVE-2018-8034: The host name verification when using TLS with the
 WebSocket client was missing. It is now enabled by default (bsc#1102379).

CVE-2018-8037: If an async request was completed by the application at
 the same time as the container triggered the async timeout, a race
 condition existed that could have resulted in a user seeing a response
 intended for a different user. An additional issue was present in the
 NIO and NIO2 connectors that did not correctly track the closure of the
 connection when an async request was completed by the application and
 timed out by the container at the same time. This could also have
 resulted in a user seeing a response intended for another user
 (bsc#1102410).

Bug fixes:
Avoid overwriting of customer's configuration during update (bsc#1067720)

Disable adding OSGi metadata to JAR files See changelog at [link moved to references](markt
 )" );
	script_tag( name: "affected", value: "'tomcat' package(s) on SUSE Linux Enterprise Module for Web Scripting 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "tomcat", rpm: "tomcat~9.0.10~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-admin-webapps", rpm: "tomcat-admin-webapps~9.0.10~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-el-3_0-api", rpm: "tomcat-el-3_0-api~9.0.10~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsp-2_3-api", rpm: "tomcat-jsp-2_3-api~9.0.10~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-lib", rpm: "tomcat-lib~9.0.10~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-servlet-4_0-api", rpm: "tomcat-servlet-4_0-api~9.0.10~3.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-webapps", rpm: "tomcat-webapps~9.0.10~3.3.1", rls: "SLES15.0" ) )){
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

