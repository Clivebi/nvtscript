if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881927" );
	script_version( "2020-03-13T10:06:41+0000" );
	script_tag( name: "last_modification", value: "2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)" );
	script_tag( name: "creation_date", value: "2014-05-02 10:05:18 +0530 (Fri, 02 May 2014)" );
	script_cve_id( "CVE-2013-4286", "CVE-2013-4322", "CVE-2014-0050", "CVE-2012-3544" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CentOS Update for tomcat6 CESA-2014:0429 centos6" );
	script_tag( name: "affected", value: "tomcat6 on CentOS 6" );
	script_tag( name: "insight", value: "Apache Tomcat is a servlet container for the Java Servlet and JavaServer
Pages (JSP) technologies.

It was found that when Tomcat processed a series of HTTP requests in which
at least one request contained either multiple content-length headers, or
one content-length header with a chunked transfer-encoding header, Tomcat
would incorrectly handle the request. A remote attacker could use this flaw
to poison a web cache, perform cross-site scripting (XSS) attacks, or
obtain sensitive information from other requests. (CVE-2013-4286)

It was discovered that the fix for CVE-2012-3544 did not properly resolve a
denial of service flaw in the way Tomcat processed chunk extensions and
trailing headers in chunked requests. A remote attacker could use this flaw
to send an excessively long request that, when processed by Tomcat, could
consume network bandwidth, CPU, and memory on the Tomcat server. Note that
chunked transfer encoding is enabled by default. (CVE-2013-4322)

A denial of service flaw was found in the way Apache Commons FileUpload
handled small-sized buffers used by MultipartStream. A remote attacker
could use this flaw to create a malformed Content-Type header for a
multipart request, causing JBoss Web to enter an infinite loop when
processing such an incoming request. (CVE-2014-0050)

All Tomcat users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. Tomcat must be
restarted for this update to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:0429" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-April/020265.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat6'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "tomcat6", rpm: "tomcat6~6.0.24~64.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-admin-webapps", rpm: "tomcat6-admin-webapps~6.0.24~64.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-docs-webapp", rpm: "tomcat6-docs-webapp~6.0.24~64.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-el-2.1-api", rpm: "tomcat6-el-2.1-api~6.0.24~64.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-javadoc", rpm: "tomcat6-javadoc~6.0.24~64.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-jsp-2.1-api", rpm: "tomcat6-jsp-2.1-api~6.0.24~64.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-lib", rpm: "tomcat6-lib~6.0.24~64.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-servlet-2.5-api", rpm: "tomcat6-servlet-2.5-api~6.0.24~64.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-webapps", rpm: "tomcat6-webapps~6.0.24~64.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

