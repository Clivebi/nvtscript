if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841593" );
	script_version( "2020-11-12T11:08:16+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 11:08:16 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2013-10-18 09:16:14 +0530 (Fri, 18 Oct 2013)" );
	script_cve_id( "CVE-2013-4396", "CVE-2013-1056" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for xorg-server USN-1990-1" );
	script_tag( name: "affected", value: "xorg-server on Ubuntu 13.04,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Pedro Ribeiro discovered that the X.Org X server incorrectly handled
memory operations when handling ImageText requests. An attacker could use
this issue to cause X.Org to crash, or to possibly execute arbitrary code.
(CVE-2013-4396)

It was discovered that non-root X.Org X servers such as Xephyr incorrectly
used cached xkb files. A local attacker could use this flaw to cause an xkb
cache file to be loaded by another user, resulting in a denial of service.
(CVE-2013-1056)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "1990-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1990-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-server'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(12\\.04 LTS|12\\.10|13\\.04)" );
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
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "2:1.11.4-0ubuntu10.14", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core-lts-quantal", ver: "2:1.13.0-0ubuntu6.1~precise4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core-lts-raring", ver: "2:1.13.3-0ubuntu6~precise3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "2:1.13.0-0ubuntu6.4", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.04"){
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "2:1.13.3-0ubuntu6.2", rls: "UBUNTU13.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

