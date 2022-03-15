if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842938" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-08 15:52:54 +0530 (Tue, 08 Nov 2016)" );
	script_cve_id( "CVE-2015-0245" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for dbus USN-3116-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dbus'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that DBus incorrectly
  validated the source of ActivationFailure signals. A local attacker could use
  this issue to cause a denial of service. This issue only applied to Ubuntu
  12.04 LTS and Ubuntu 14.04 LTS. (CVE-2015-0245)

It was discovered that DBus incorrectly handled certain format strings. A
local attacker could use this issue to cause a denial of service, or
possibly execute arbitrary code. This issue is only exposed to unprivileged
users when the fix for CVE-2015-0245 is not applied, hence this issue is
only likely to affect Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. Ubuntu 16.04
LTS and Ubuntu 16.10 have been updated as a preventative measure in the
event that a new attack vector for this issue is discovered.
(No CVE number)" );
	script_tag( name: "affected", value: "dbus on Ubuntu 16.04 LTS,
  Ubuntu 16.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3116-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3116-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|16\\.04 LTS|16\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "dbus", ver: "1.6.18-0ubuntu4.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libdbus-1-3", ver: "1.6.18-0ubuntu4.4", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "dbus", ver: "1.4.18-1ubuntu1.8", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libdbus-1-3", ver: "1.4.18-1ubuntu1.8", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "dbus", ver: "1.10.6-1ubuntu3.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libdbus-1-3", ver: "1.10.6-1ubuntu3.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "dbus", ver: "1.10.10-1ubuntu1.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libdbus-1-3", ver: "1.10.10-1ubuntu1.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

