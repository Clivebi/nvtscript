if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882434" );
	script_version( "2020-03-13T10:06:41+0000" );
	script_tag( name: "last_modification", value: "2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-03-24 06:15:02 +0100 (Thu, 24 Mar 2016)" );
	script_cve_id( "CVE-2014-7810" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for tomcat6 CESA-2016:0492 centos6" );
	script_tag( name: "summary", value: "Check the version of tomcat6" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Apache Tomcat is a servlet container for
the Java Servlet and JavaServer Pages (JSP) technologies.

It was found that the expression language resolver evaluated expressions
within a privileged code section. A malicious web application could use
this flaw to bypass security manager protections. (CVE-2014-7810)

This update also fixes the following bug:

  * Previously, using a New I/O (NIO) connector in the Apache Tomcat 6
servlet resulted in a large memory leak. An upstream patch has been applied
to fix this bug, and the memory leak no longer occurs. (BZ#1301646)

All Tomcat 6 users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. Tomcat must be
restarted for this update to take effect." );
	script_tag( name: "affected", value: "tomcat6 on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:0492" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-March/021766.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "tomcat6", rpm: "tomcat6~6.0.24~94.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-admin-webapps", rpm: "tomcat6-admin-webapps~6.0.24~94.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-docs-webapp", rpm: "tomcat6-docs-webapp~6.0.24~94.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-el-2.1-api", rpm: "tomcat6-el-2.1-api~6.0.24~94.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-javadoc", rpm: "tomcat6-javadoc~6.0.24~94.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-jsp-2.1-api", rpm: "tomcat6-jsp-2.1-api~6.0.24~94.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-lib", rpm: "tomcat6-lib~6.0.24~94.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-servlet-2.5-api", rpm: "tomcat6-servlet-2.5-api~6.0.24~94.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-webapps", rpm: "tomcat6-webapps~6.0.24~94.el6_7", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

