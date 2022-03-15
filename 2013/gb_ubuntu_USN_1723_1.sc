if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1723-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841319" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-02-15 11:25:30 +0530 (Fri, 15 Feb 2013)" );
	script_cve_id( "CVE-2012-5624", "CVE-2012-6093", "CVE-2013-0254" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_xref( name: "USN", value: "1723-1" );
	script_name( "Ubuntu Update for qt4-x11 USN-1723-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qt4-x11'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|11\\.10|10\\.04 LTS|12\\.10)" );
	script_tag( name: "affected", value: "qt4-x11 on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Richard J. Moore and Peter Hartmann discovered that Qt allowed redirecting
  requests from http to file schemes. If an attacker were able to perform a
  man-in-the-middle attack, this flaw could be exploited to view sensitive
  information. This issue only affected Ubuntu 11.10, Ubuntu 12.04 LTS,
  and Ubuntu 12.10. (CVE-2012-5624)

  Stephen Cheng discovered that Qt may report incorrect errors when ssl
  certificate verification fails. (CVE-2012-6093)

  Tim Brown and Mark Lowe discovered that Qt incorrectly used weak
  permissions on shared memory segments. A local attacker could use this
  issue to view sensitive information, or modify program data belonging to
  other users. (CVE-2013-0254)" );
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
	if(( res = isdpkgvuln( pkg: "libqt4-core", ver: "4:4.8.1-0ubuntu4.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libqt4-network", ver: "4:4.8.1-0ubuntu4.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "libqt4-core", ver: "4:4.7.4-0ubuntu8.3", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libqt4-network", ver: "4:4.7.4-0ubuntu8.3", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libqt4-core", ver: "4:4.6.2-0ubuntu5.6", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libqt4-network", ver: "4:4.6.2-0ubuntu5.6", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libqt4-core", ver: "4:4.8.3+dfsg-0ubuntu3.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libqt4-network", ver: "4:4.8.3+dfsg-0ubuntu3.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

