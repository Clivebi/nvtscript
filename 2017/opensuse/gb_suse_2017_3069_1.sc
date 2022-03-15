if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851651" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-24 07:29:59 +0100 (Fri, 24 Nov 2017)" );
	script_cve_id( "CVE-2017-12617", "CVE-2017-5664", "CVE-2017-7674" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-23 19:29:00 +0000 (Tue, 23 Apr 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for tomcat (openSUSE-SU-2017:3069-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tomcat fixes the following issues:

  Security issues fixed:

  - CVE-2017-5664: A problem in handling error pages was fixed, to avoid
  potential file overwrites during error page handling. (bsc#1042910).

  - CVE-2017-7674: A CORS Filter issue could lead to client and server side
  cache poisoning (bsc#1053352)

  - CVE-2017-12617: A remote code execution possibility via JSP Upload was
  fixed (bsc#1059554)

  Non security bugs fixed:

  - Fix tomcat-digest classpath error (bsc#977410)

  - Fix packaged /etc/alternatives symlinks for api libs that caused rpm -V
  to report link mismatch (bsc#1019016)

  This update was imported from the SUSE:SLE-12-SP2:Update update project." );
	script_tag( name: "affected", value: "tomcat on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:3069-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "tomcat", rpm: "tomcat~8.0.43~6.13.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-admin-webapps", rpm: "tomcat-admin-webapps~8.0.43~6.13.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-docs-webapp", rpm: "tomcat-docs-webapp~8.0.43~6.13.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-el-3_0-api", rpm: "tomcat-el-3_0-api~8.0.43~6.13.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-embed", rpm: "tomcat-embed~8.0.43~6.13.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-javadoc", rpm: "tomcat-javadoc~8.0.43~6.13.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsp-2_3-api", rpm: "tomcat-jsp-2_3-api~8.0.43~6.13.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsvc", rpm: "tomcat-jsvc~8.0.43~6.13.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-lib", rpm: "tomcat-lib~8.0.43~6.13.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-servlet-3_1-api", rpm: "tomcat-servlet-3_1-api~8.0.43~6.13.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-webapps", rpm: "tomcat-webapps~8.0.43~6.13.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "tomcat", rpm: "tomcat~8.0.43~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-admin-webapps", rpm: "tomcat-admin-webapps~8.0.43~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-docs-webapp", rpm: "tomcat-docs-webapp~8.0.43~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-el-3_0-api", rpm: "tomcat-el-3_0-api~8.0.43~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-embed", rpm: "tomcat-embed~8.0.43~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-javadoc", rpm: "tomcat-javadoc~8.0.43~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsp-2_3-api", rpm: "tomcat-jsp-2_3-api~8.0.43~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsvc", rpm: "tomcat-jsvc~8.0.43~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-lib", rpm: "tomcat-lib~8.0.43~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-servlet-3_1-api", rpm: "tomcat-servlet-3_1-api~8.0.43~9.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-webapps", rpm: "tomcat-webapps~8.0.43~9.1", rls: "openSUSELeap42.3" ) )){
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
