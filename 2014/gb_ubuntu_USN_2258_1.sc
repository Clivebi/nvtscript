if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841877" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-01 22:37:34 +0530 (Tue, 01 Jul 2014)" );
	script_cve_id( "CVE-2014-4617" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for gnupg USN-2258-1" );
	script_tag( name: "affected", value: "gnupg on Ubuntu 14.04 LTS,
  Ubuntu 13.10,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "Jean-Ren&#233  Reinhard, Olivier Levillain and Florian Maury
discovered that GnuPG incorrectly handled certain OpenPGP messages. If a user or
automated system were tricked into processing a specially-crafted message, GnuPG
could consume resources, resulting in a denial of service." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2258-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2258-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnupg'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|10\\.04 LTS|13\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "gnupg", ver: "1.4.16-1ubuntu2.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gnupg2", ver: "2.0.22-3ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "gnupg", ver: "1.4.11-3ubuntu2.6", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gnupg2", ver: "2.0.17-2ubuntu2.12.04.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "gnupg", ver: "1.4.10-2ubuntu1.6", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gnupg2", ver: "2.0.14-1ubuntu1.7", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "gnupg", ver: "1.4.14-1ubuntu2.2", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gnupg2", ver: "2.0.20-1ubuntu3.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

