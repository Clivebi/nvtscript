if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841691" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-27 11:22:27 +0530 (Mon, 27 Jan 2014)" );
	script_cve_id( "CVE-2013-1740" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_name( "Ubuntu Update for nss USN-2088-1" );
	script_tag( name: "affected", value: "nss on Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "Brian Smith discovered that NSS incorrectly handled the TLS
False Start feature. If a remote attacker were able to perform a
man-in-the-middle attack, this flaw could be exploited to spoof SSL servers." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2088-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2088-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nss'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|10\\.04 LTS|13\\.10|12\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libnss3", ver: "3.15.4-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libnss3-1d", ver: "3.15.4-0ubuntu0.10.04.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libnss3:i386", ver: "2:3.15.4-0ubuntu0.13.10.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libnss3", ver: "3.15.4-0ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

