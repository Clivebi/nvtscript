if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-March/019640.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881689" );
	script_version( "2020-03-13T10:06:41+0000" );
	script_tag( name: "last_modification", value: "2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)" );
	script_tag( name: "creation_date", value: "2013-03-15 09:52:48 +0530 (Fri, 15 Mar 2013)" );
	script_cve_id( "CVE-2012-3546", "CVE-2012-4534", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_xref( name: "CESA", value: "2013:0623" );
	script_name( "CentOS Update for tomcat6 CESA-2013:0623 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat6'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "tomcat6 on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Apache Tomcat is a servlet container.

  It was found that when an application used FORM authentication, along with
  another component that calls request.setUserPrincipal() before the call to
  FormAuthenticator#authenticate() (such as the Single-Sign-On valve), it was
  possible to bypass the security constraint checks in the FORM authenticator
  by appending _security_check  to the end of a URL. A remote attacker
  with an authenticated session on an affected application could use this
  flaw to circumvent authorization controls, and thereby access resources not
  permitted by the roles associated with their authenticated session.
  (CVE-2012-3546)

  A flaw was found in the way Tomcat handled sendfile operations when using
  the HTTP NIO (Non-Blocking I/O) connector and HTTPS. A remote attacker
  could use this flaw to cause a denial of service (infinite loop). The HTTP
  blocking IO (BIO) connector, which is not vulnerable to this issue, is used
  by default in Red Hat Enterprise Linux 6. (CVE-2012-4534)

  Multiple weaknesses were found in the Tomcat DIGEST authentication
  implementation, effectively reducing the security normally provided by
  DIGEST authentication. A remote attacker could use these flaws to perform
  replay attacks in some circumstances. (CVE-2012-5885, CVE-2012-5886,
  CVE-2012-5887)

  Users of Tomcat should upgrade to these updated packages, which correct
  these issues. Tomcat must be restarted for this update to take effect." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
	if(( res = isrpmvuln( pkg: "tomcat6", rpm: "tomcat6~6.0.24~52.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-admin-webapps", rpm: "tomcat6-admin-webapps~6.0.24~52.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-docs-webapp", rpm: "tomcat6-docs-webapp~6.0.24~52.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-el-2.1-api", rpm: "tomcat6-el-2.1-api~6.0.24~52.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-javadoc", rpm: "tomcat6-javadoc~6.0.24~52.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-jsp-2.1-api", rpm: "tomcat6-jsp-2.1-api~6.0.24~52.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-lib", rpm: "tomcat6-lib~6.0.24~52.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-servlet-2.5-api", rpm: "tomcat6-servlet-2.5-api~6.0.24~52.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-webapps", rpm: "tomcat6-webapps~6.0.24~52.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

