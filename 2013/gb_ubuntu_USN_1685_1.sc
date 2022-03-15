if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1685-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841274" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-01-15 18:07:42 +0530 (Tue, 15 Jan 2013)" );
	script_cve_id( "CVE-2012-3546", "CVE-2012-4431", "CVE-2012-4534" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "USN", value: "1685-1" );
	script_name( "Ubuntu Update for tomcat7 USN-1685-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat7'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|10\\.04 LTS|12\\.10)" );
	script_tag( name: "affected", value: "tomcat7 on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Tomcat incorrectly performed certain security
  constraint checks in the FORM authenticator. A remote attacker could
  possibly use this flaw with a specially-crafted URI to bypass security
  constraint checks. This issue only affected Ubuntu 10.04 LTS, Ubuntu 11.10
  and Ubuntu 12.04 LTS. (CVE-2012-3546)

  It was discovered that Tomcat incorrectly handled requests that lack a
  session identifier. A remote attacker could possibly use this flaw to
  bypass the cross-site request forgery protection. (CVE-2012-4431)

  It was discovered that Tomcat incorrectly handled sendfile and HTTPS when
  the NIO connector is used. A remote attacker could use this flaw to cause
  Tomcat to stop responding, resulting in a denial of service. This issue
  only affected Ubuntu 10.04 LTS, Ubuntu 11.10 and Ubuntu 12.04 LTS.
  (CVE-2012-4534)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtomcat6-java", ver: "6.0.35-1ubuntu3.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "libtomcat6-java", ver: "6.0.32-5ubuntu1.4", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtomcat6-java", ver: "6.0.24-2ubuntu1.12", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.30-0ubuntu1.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
