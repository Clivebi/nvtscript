if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842538" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-20 06:27:51 +0100 (Fri, 20 Nov 2015)" );
	script_cve_id( "CVE-2012-3425", "CVE-2015-7981", "CVE-2015-8126" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libpng USN-2815-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpng'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mikulas Patocka discovered that libpng
incorrectly handled certain large fields. If a user or automated system using
libpng were tricked into opening a specially crafted image, an attacker could
exploit this to cause libpng to crash, leading to a denial of service. This
issue only affected Ubuntu 12.04 LTS. (CVE-2012-3425)

Qixue Xiao discovered that libpng incorrectly handled certain time values.
If a user or automated system using libpng were tricked into opening a
specially crafted image, an attacker could exploit this to cause libpng to
crash, leading to a denial of service. (CVE-2015-7981)

It was discovered that libpng incorrectly handled certain small bit-depth
values. If a user or automated system using libpng were tricked into
opening a specially crafted image, an attacker could exploit this to cause
a denial of service or execute code with the privileges of the user
invoking the program. (CVE-2015-8126)" );
	script_tag( name: "affected", value: "libpng on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2815-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2815-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|12\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.04"){
	if(( res = isdpkgvuln( pkg: "libpng12-0:amd64", ver: "1.2.51-0ubuntu3.15.04.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpng12-0:i386", ver: "1.2.51-0ubuntu3.15.04.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpng12-0:amd64", ver: "1.2.50-1ubuntu2.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpng12-0:i386", ver: "1.2.50-1ubuntu2.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpng12-0", ver: "1.2.46-3ubuntu4.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libpng12-0:i386", ver: "1.2.51-0ubuntu3.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpng12-0:amd64", ver: "1.2.51-0ubuntu3.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

