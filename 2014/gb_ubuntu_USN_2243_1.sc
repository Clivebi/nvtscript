if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841855" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-17 10:05:45 +0530 (Tue, 17 Jun 2014)" );
	script_cve_id( "CVE-2014-1533", "CVE-2014-1534", "CVE-2014-1536", "CVE-2014-1537", "CVE-2014-1538", "CVE-2014-1540", "CVE-2014-1541", "CVE-2014-1542" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for firefox USN-2243-1" );
	script_tag( name: "affected", value: "firefox on Ubuntu 14.04 LTS,
  Ubuntu 13.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Gary Kwong, Christoph Diehl, Christian Holler, Hannes Verschore,
Jan de Mooij, Ryan VanderMeulen, Jeff Walden, Kyle Huey, Jesse Ruderman, Gregor
Wagner, Benoit Jacob and Karl Tomlinson discovered multiple memory safety
issues in Firefox. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2014-1533,
CVE-2014-1534)

Abhishek Arya discovered multiple use-after-free and out-of-bounds read
issues in Firefox. An attacker could potentially exploit these to cause
a denial of service via application crash or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2014-1536,
CVE-2014-1537, CVE-2014-1538)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in the
event listener manager. An attacker could potentially exploit this to
cause a denial of service via application crash or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2014-1540)

A use-after-free was discovered in the SMIL animation controller. An
attacker could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2014-1541)

Holger Fuhrmannek discovered a buffer overflow in Web Audio. An attacker
could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2014-1542)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2243-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2243-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|13\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "firefox", ver: "30.0+build1-0ubuntu0.14.04.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "30.0+build1-0ubuntu0.12.04.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "firefox", ver: "30.0+build1-0ubuntu0.13.10.3", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

