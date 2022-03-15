if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882796" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-02 18:05:42 +0530 (Thu, 02 Nov 2017)" );
	script_cve_id( "CVE-2017-12615", "CVE-2017-12617", "CVE-2017-5647", "CVE-2017-7674" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 16:30:00 +0000 (Mon, 15 Apr 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for tomcat CESA-2017:3081 centos7" );
	script_tag( name: "summary", value: "Check the version of tomcat" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Apache Tomcat is a servlet container for
the Java Servlet and JavaServer Pages (JSP) technologies.

Security Fix(es):

  * A vulnerability was discovered in Tomcat's handling of pipelined requests
when 'Sendfile' was used. If sendfile processing completed quickly, it was
possible for the Processor to be added to the processor cache twice. This
could lead to invalid responses or information disclosure. (CVE-2017-5647)

  * Two vulnerabilities were discovered in Tomcat where if a servlet context
was configured with readonly=false and HTTP PUT requests were allowed, an
attacker could upload a JSP file to that context and achieve code
execution. (CVE-2017-12615, CVE-2017-12617)

  * A vulnerability was discovered in Tomcat where the CORS Filter did not
send a 'Vary: Origin' HTTP header. This potentially allowed sensitive data
to be leaked to other visitors through both client-side and server-side
caches. (CVE-2017-7674)" );
	script_tag( name: "affected", value: "tomcat on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:3081" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-October/022611.html" );
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
	if(( res = isrpmvuln( pkg: "tomcat", rpm: "tomcat~7.0.76~3.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-admin-webapps", rpm: "tomcat-admin-webapps~7.0.76~3.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-docs-webapp", rpm: "tomcat-docs-webapp~7.0.76~3.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-el-2.2-api", rpm: "tomcat-el-2.2-api~7.0.76~3.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-javadoc", rpm: "tomcat-javadoc~7.0.76~3.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-jsp-2.2-api", rpm: "tomcat-jsp-2.2-api~7.0.76~3.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-jsvc", rpm: "tomcat-jsvc~7.0.76~3.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-lib", rpm: "tomcat-lib~7.0.76~3.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-servlet-3.0-api", rpm: "tomcat-servlet-3.0-api~7.0.76~3.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-webapps", rpm: "tomcat-webapps~7.0.76~3.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

