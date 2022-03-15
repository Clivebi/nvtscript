if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881740" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-05-31 09:51:25 +0530 (Fri, 31 May 2013)" );
	script_cve_id( "CVE-2013-1976" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "CentOS Update for tomcat5 CESA-2013:0870 centos5" );
	script_xref( name: "CESA", value: "2013:0870" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-May/019748.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat5'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "tomcat5 on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Apache Tomcat is a servlet container for the Java Servlet and JavaServer
  Pages (JSP) technologies.

  A flaw was found in the way the tomcat5 init script handled the
  catalina.out log file. A malicious web application deployed on Tomcat
  could use this flaw to perform a symbolic link attack to change the
  ownership of an arbitrary system file to that of the tomcat user, allowing
  them to escalate their privileges to root. (CVE-2013-1976)

  Note: With this update, /var/log/tomcat5/catalina.out has been moved to the
  /var/log/tomcat5-initd.log file.

  Red Hat would like to thank Simon Fayer of Imperial College London for
  reporting this issue.

  Users of Tomcat are advised to upgrade to these updated packages, which
  correct this issue. Tomcat must be restarted for this update to take
  effect." );
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
	if(( res = isrpmvuln( pkg: "tomcat5", rpm: "tomcat5~5.5.23~0jpp.40.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-admin-webapps", rpm: "tomcat5-admin-webapps~5.5.23~0jpp.40.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-common-lib", rpm: "tomcat5-common-lib~5.5.23~0jpp.40.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jasper", rpm: "tomcat5-jasper~5.5.23~0jpp.40.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jasper-javadoc", rpm: "tomcat5-jasper-javadoc~5.5.23~0jpp.40.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jsp-2.0-api", rpm: "tomcat5-jsp-2.0-api~5.5.23~0jpp.40.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jsp-2.0-api-javadoc", rpm: "tomcat5-jsp-2.0-api-javadoc~5.5.23~0jpp.40.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-server-lib", rpm: "tomcat5-server-lib~5.5.23~0jpp.40.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-servlet-2.4-api", rpm: "tomcat5-servlet-2.4-api~5.5.23~0jpp.40.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-servlet-2.4-api-javadoc", rpm: "tomcat5-servlet-2.4-api-javadoc~5.5.23~0jpp.40.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-webapps", rpm: "tomcat5-webapps~5.5.23~0jpp.40.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

