if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812058" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-30 09:23:08 +0100 (Mon, 30 Oct 2017)" );
	script_cve_id( "CVE-2017-12615", "CVE-2017-12617", "CVE-2017-5647", "CVE-2017-5664" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 16:30:00 +0000 (Mon, 15 Apr 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for tomcat6 RHSA-2017:3080-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat6'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Apache Tomcat is a servlet container for
  the Java Servlet and JavaServer Pages (JSP) technologies.

Security Fix(es):

  * A vulnerability was discovered in Tomcat's handling of pipelined requests
when 'Sendfile' was used. If sendfile processing completed quickly, it was
possible for the Processor to be added to the processor cache twice. This
could lead to invalid responses or information disclosure. (CVE-2017-5647)

  * A vulnerability was discovered in the error page mechanism in Tomcat's
DefaultServlet implementation. A crafted HTTP request could cause undesired
side effects, possibly including the removal or replacement of the custom
error page. (CVE-2017-5664)

  * Two vulnerabilities were discovered in Tomcat where if a servlet context
was configured with readonly=false and HTTP PUT requests were allowed, an
attacker could upload a JSP file to that context and achieve code
execution. (CVE-2017-12615, CVE-2017-12617)" );
	script_tag( name: "affected", value: "tomcat6 on
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2017:3080-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2017-October/msg00039.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "tomcat6", rpm: "tomcat6~6.0.24~111.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-el-2.1-api", rpm: "tomcat6-el-2.1-api~6.0.24~111.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-jsp-2.1-api", rpm: "tomcat6-jsp-2.1-api~6.0.24~111.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-lib", rpm: "tomcat6-lib~6.0.24~111.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat6-servlet-2.5-api", rpm: "tomcat6-servlet-2.5-api~6.0.24~111.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

