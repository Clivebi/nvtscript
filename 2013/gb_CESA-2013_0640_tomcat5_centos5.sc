if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-March/019645.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881687" );
	script_version( "2020-03-13T10:06:41+0000" );
	script_tag( name: "last_modification", value: "2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)" );
	script_tag( name: "creation_date", value: "2013-03-15 09:52:23 +0530 (Fri, 15 Mar 2013)" );
	script_cve_id( "CVE-2012-3546", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_xref( name: "CESA", value: "2013:0640" );
	script_name( "CentOS Update for tomcat5 CESA-2013:0640 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat5'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "tomcat5 on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Apache Tomcat is a servlet container.

  It was found that when an application used FORM authentication, along with
  another component that calls request.setUserPrincipal() before the call to
  FormAuthenticator#authenticate() (such as the Single-Sign-On valve), it was
  possible to bypass the security constraint checks in the FORM authenticator
  by appending '/j_security_check' to the end of a URL. A remote attacker
  with an authenticated session on an affected application could use this
  flaw to circumvent authorization controls, and thereby access resources not
  permitted by the roles associated with their authenticated session.
  (CVE-2012-3546)

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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "tomcat5", rpm: "tomcat5~5.5.23~0jpp.38.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-admin-webapps", rpm: "tomcat5-admin-webapps~5.5.23~0jpp.38.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-common-lib", rpm: "tomcat5-common-lib~5.5.23~0jpp.38.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jasper", rpm: "tomcat5-jasper~5.5.23~0jpp.38.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jasper-javadoc", rpm: "tomcat5-jasper-javadoc~5.5.23~0jpp.38.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jsp-2.0-api", rpm: "tomcat5-jsp-2.0-api~5.5.23~0jpp.38.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jsp-2.0-api-javadoc", rpm: "tomcat5-jsp-2.0-api-javadoc~5.5.23~0jpp.38.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-server-lib", rpm: "tomcat5-server-lib~5.5.23~0jpp.38.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-servlet-2.4-api", rpm: "tomcat5-servlet-2.4-api~5.5.23~0jpp.38.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-servlet-2.4-api-javadoc", rpm: "tomcat5-servlet-2.4-api-javadoc~5.5.23~0jpp.38.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-webapps", rpm: "tomcat5-webapps~5.5.23~0jpp.38.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

