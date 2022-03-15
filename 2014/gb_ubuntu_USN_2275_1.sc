if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841891" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-15 17:01:14 +0530 (Tue, 15 Jul 2014)" );
	script_cve_id( "CVE-2014-3477", "CVE-2014-3532", "CVE-2014-3533" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Ubuntu Update for dbus USN-2275-1" );
	script_tag( name: "affected", value: "dbus on Ubuntu 14.04 LTS,
  Ubuntu 13.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Alban Crequy discovered that dbus-daemon incorrectly sent
AccessDenied errors to the service instead of the client when enforcing
permissions. A local user can use this issue to possibly deny access to the
service. (CVE-2014-3477)

Alban Crequy discovered that dbus-daemon incorrectly handled certain file
descriptors. A local attacker could use this issue to cause services or
clients to disconnect, resulting in a denial of service. (CVE-2014-3532,
CVE-2014-3533)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2275-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2275-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dbus'
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
	if(( res = isdpkgvuln( pkg: "dbus", ver: "1.6.18-0ubuntu4.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libdbus-1-3:i386", ver: "1.6.18-0ubuntu4.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "dbus", ver: "1.4.18-1ubuntu1.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libdbus-1-3", ver: "1.4.18-1ubuntu1.5", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "dbus", ver: "1.6.12-0ubuntu10.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libdbus-1-3:i386", ver: "1.6.12-0ubuntu10.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

