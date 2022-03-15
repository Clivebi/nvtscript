if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882757" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-28 07:24:11 +0200 (Fri, 28 Jul 2017)" );
	script_cve_id( "CVE-2017-5648", "CVE-2017-5664" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-20 21:15:00 +0000 (Mon, 20 Jul 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for tomcat CESA-2017:1809 centos7" );
	script_tag( name: "summary", value: "Check the version of tomcat" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Apache Tomcat is a servlet container for
the Java Servlet and JavaServer Pages (JSP) technologies.

Security Fix(es):

  * A vulnerability was discovered in the error page mechanism in Tomcat's
DefaultServlet implementation. A crafted HTTP request could cause undesired
side effects, possibly including the removal or replacement of the custom
error page. (CVE-2017-5664)

  * A vulnerability was discovered in Tomcat. When running an untrusted
application under a SecurityManager it was possible, under some
circumstances, for that application to retain references to the request or
response objects and thereby access and/or modify information associated
with another web application. (CVE-2017-5648)" );
	script_tag( name: "affected", value: "tomcat on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:1809" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-July/022511.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "tomcat", rpm: "tomcat~7.0.69~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-admin-webapps", rpm: "tomcat-admin-webapps~7.0.69~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-docs-webapp", rpm: "tomcat-docs-webapp~7.0.69~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-el-2.2-api", rpm: "tomcat-el-2.2-api~7.0.69~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-javadoc", rpm: "tomcat-javadoc~7.0.69~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-jsp-2.2-api", rpm: "tomcat-jsp-2.2-api~7.0.69~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-jsvc", rpm: "tomcat-jsvc~7.0.69~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-lib", rpm: "tomcat-lib~7.0.69~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-servlet-3.0-api", rpm: "tomcat-servlet-3.0-api~7.0.69~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-webapps", rpm: "tomcat-webapps~7.0.69~12.el7_3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

