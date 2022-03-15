if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841686" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-20 10:07:30 +0530 (Mon, 20 Jan 2014)" );
	script_cve_id( "CVE-2011-4971", "CVE-2013-0179", "CVE-2013-7239" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for memcached USN-2080-1" );
	script_tag( name: "affected", value: "memcached on Ubuntu 13.10,
  Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Stefan Bucur discovered that Memcached incorrectly handled
certain large body lengths. A remote attacker could use this issue to cause
Memcached to crash, resulting in a denial of service. (CVE-2011-4971)

Jeremy Sowden discovered that Memcached incorrectly handled logging certain
details when the -vv option was used. An attacker could use this issue to
cause Memcached to crash, resulting in a denial of service. (CVE-2013-0179)

It was discovered that Memcached incorrectly handled SASL authentication.
A remote attacker could use this issue to bypass SASL authentication
completely. This issue only affected Ubuntu 12.10, Ubuntu 13.04 and Ubuntu
13.10. (CVE-2013-7239)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2080-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2080-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'memcached'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.10|12\\.04 LTS|13\\.10|13\\.04)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "memcached", ver: "1.4.14-0ubuntu1.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "memcached", ver: "1.4.13-0ubuntu2.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "memcached", ver: "1.4.14-0ubuntu4.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "memcached", ver: "1.4.14-0ubuntu1.13.04.1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

