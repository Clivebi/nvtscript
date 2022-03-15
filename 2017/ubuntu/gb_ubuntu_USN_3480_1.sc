if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843364" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-16 07:28:49 +0100 (Thu, 16 Nov 2017)" );
	script_cve_id( "CVE-2017-14177", "CVE-2017-14180" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-15 13:20:00 +0000 (Thu, 15 Feb 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for apport USN-3480-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apport'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Sander Bos discovered that Apport
incorrectly handled core dumps for setuid binaries. A local attacker could
use this issue to perform a denial of service via resource exhaustion or
possibly gain root privileges. (CVE-2017-14177)

Sander Bos discovered that Apport incorrectly handled core dumps for processes
in a different PID namespace. A local attacker could use this issue to perform
a denial of service via resource exhaustion or possibly gain root privileges.
(CVE-2017-14180)" );
	script_tag( name: "affected", value: "apport on Ubuntu 17.10,
  Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3480-1" );
	script_xref( name: "URL", value: "https://usn.ubuntu.com/usn/usn-3480-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|17\\.04|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "apport", ver: "2.14.1-0ubuntu3.27", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "apport", ver: "2.20.7-0ubuntu3.4", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "apport", ver: "2.20.4-0ubuntu4.7", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "apport", ver: "2.20.1-0ubuntu2.12", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

