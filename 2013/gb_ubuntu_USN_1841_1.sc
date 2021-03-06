if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841442" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-05-31 09:57:48 +0530 (Fri, 31 May 2013)" );
	script_cve_id( "CVE-2012-3544", "CVE-2013-2067", "CVE-2013-2071" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for tomcat7 USN-1841-1" );
	script_xref( name: "USN", value: "1841-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1841-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat7'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|10\\.04 LTS|12\\.10|13\\.04)" );
	script_tag( name: "affected", value: "tomcat7 on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Tomcat incorrectly handled certain requests
  submitted using chunked transfer encoding. A remote attacker could use this
  flaw to cause the Tomcat server to stop responding, resulting in a denial
  of service. This issue only affected Ubuntu 10.04 LTS and Ubuntu 12.04 LTS.
  (CVE-2012-3544)

  It was discovered that Tomcat incorrectly handled certain authentication
  requests. A remote attacker could possibly use this flaw to inject a
  request that would get executed with a victim's credentials. This issue
  only affected Ubuntu 10.04 LTS, Ubuntu 12.04 LTS, and Ubuntu 12.10.
  (CVE-2013-2067)

  It was discovered that Tomcat sometimes exposed elements of a previous
  request to the current request. This could allow a remote attacker to
  possibly obtain sensitive information. This issue only affected Ubuntu
  12.10 and Ubuntu 13.04. (CVE-2013-2071)" );
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
	if(( res = isdpkgvuln( pkg: "libtomcat6-java", ver: "6.0.35-1ubuntu3.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtomcat6-java", ver: "6.0.24-2ubuntu1.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.30-0ubuntu1.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.35-1~exp2ubuntu1.1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

