if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841605" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-10-29 16:50:28 +0530 (Tue, 29 Oct 2013)" );
	script_cve_id( "CVE-2012-4412", "CVE-2012-4424", "CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4237", "CVE-2013-4332" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for eglibc USN-1991-1" );
	script_tag( name: "affected", value: "eglibc on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that the GNU C Library incorrectly handled the strcoll()
function. An attacker could use this issue to cause a denial of service, or
possibly execute arbitrary code. (CVE-2012-4412, CVE-2012-4424)

It was discovered that the GNU C Library incorrectly handled multibyte
characters in the regular expression matcher. An attacker could use this
issue to cause a denial of service. (CVE-2013-0242)

It was discovered that the GNU C Library incorrectly handled large numbers
of domain conversion results in the getaddrinfo() function. An attacker
could use this issue to cause a denial of service. (CVE-2013-1914)

It was discovered that the GNU C Library readdir_r() function incorrectly
handled crafted NTFS or CIFS images. An attacker could use this issue to
cause a denial of service, or possibly execute arbitrary code.
(CVE-2013-4237)

It was discovered that the GNU C Library incorrectly handled memory
allocation. An attacker could use this issue to cause a denial of service.
(CVE-2013-4332)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1991-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1991-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'eglibc'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|10\\.04 LTS|12\\.10|13\\.04)" );
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
	if(( res = isdpkgvuln( pkg: "libc6", ver: "2.15-0ubuntu10.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libc6", ver: "2.11.1-0ubuntu7.13", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libc6", ver: "2.15-0ubuntu20.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "libc6", ver: "2.17-0ubuntu5.1", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

