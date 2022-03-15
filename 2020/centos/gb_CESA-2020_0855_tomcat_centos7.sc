if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883204" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2020-1938" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-03-26 04:01:02 +0000 (Thu, 26 Mar 2020)" );
	script_name( "CentOS: Security Advisory for tomcat (CESA-2020:0855)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:0855" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-March/035669.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat'
  package(s) announced via the CESA-2020:0855 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Apache Tomcat is a servlet container for the Java Servlet and JavaServer
Pages (JSP) technologies.

Security Fix(es):

  * tomcat: Apache Tomcat AJP File Read/Inclusion Vulnerability
(CVE-2020-1938)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'tomcat' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "tomcat-7.0.76", rpm: "tomcat-7.0.76~11.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-admin-webapps", rpm: "tomcat-admin-webapps~7.0.76~11.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-docs-webapp", rpm: "tomcat-docs-webapp~7.0.76~11.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-el-2.2-api-7.0.76", rpm: "tomcat-el-2.2-api-7.0.76~11.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-javadoc", rpm: "tomcat-javadoc~7.0.76~11.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsp-2.2-api-7.0.76", rpm: "tomcat-jsp-2.2-api-7.0.76~11.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-jsvc", rpm: "tomcat-jsvc~7.0.76~11.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-lib", rpm: "tomcat-lib~7.0.76~11.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-servlet-3.0-api", rpm: "tomcat-servlet-3.0-api~7.0.76~11.el7_7", rls: "CentOS7" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat-webapps", rpm: "tomcat-webapps~7.0.76~11.el7_7", rls: "CentOS7" ) )){
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
