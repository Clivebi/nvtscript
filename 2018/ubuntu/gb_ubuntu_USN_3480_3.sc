if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843719" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_cve_id( "CVE-2017-14177", "CVE-2017-14180" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-15 13:20:00 +0000 (Thu, 15 Feb 2018)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:11:02 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for apport USN-3480-3" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(17\\.10|17\\.04|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3480-3" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3480-3/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apport'
  package(s) announced via the USN-3480-3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-3480-2 fixed regressions in Apport. The update introduced a new
regression in the container support. This update addresses the problem.

We apologize for the inconvenience.

Original advisory details:

Sander Bos discovered that Apport incorrectly handled core dumps for
setuid binaries. A local attacker could use this issue to perform a
denial of service via resource exhaustion or possibly gain root
privileges. (CVE-2017-14177)

Sander Bos discovered that Apport incorrectly handled core dumps for
processes in a different PID namespace. A local attacker could use
this issue to perform a denial of service via resource exhaustion or
possibly gain root privileges. (CVE-2017-14180)" );
	script_tag( name: "affected", value: "apport on Ubuntu 17.10,
  Ubuntu 17.04,
  Ubuntu 16.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "apport", ver: "2.20.7-0ubuntu3.7", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "apport", ver: "2.20.4-0ubuntu4.10", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "apport", ver: "2.20.1-0ubuntu2.15", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

