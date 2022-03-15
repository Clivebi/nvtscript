if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841825" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-19 11:24:57 +0530 (Mon, 19 May 2014)" );
	script_cve_id( "CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for libxfont USN-2211-1" );
	script_tag( name: "affected", value: "libxfont on Ubuntu 14.04 LTS,
  Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "Ilja van Sprundel discovered that libXfont incorrectly handled
font metadata file parsing. A local attacker could use this issue to cause
libXfont to crash, or possibly execute arbitrary code in order to gain
privileges. (CVE-2014-0209)

Ilja van Sprundel discovered that libXfont incorrectly handled X Font
Server replies. A malicious font server could return specially-crafted data
that could cause libXfont to crash, or possibly execute arbitrary code.
This issue only affected Ubuntu 10.04 LTS, Ubuntu 12.04 LTS, Ubuntu 12.10
and Ubuntu 13.10. (CVE-2014-0210, CVE-2014-0211)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2211-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2211-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxfont'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|10\\.04 LTS|13\\.10|12\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libxfont1:i386", ver: "1:1.4.7-1ubuntu0.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libxfont1", ver: "1:1.4.4-1ubuntu0.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libxfont1", ver: "1:1.4.1-1ubuntu0.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libxfont1:i386", ver: "1:1.4.6-1ubuntu0.2", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "libxfont1", ver: "1:1.4.5-2ubuntu0.12.10.2", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

