if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843341" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-13 08:36:07 +0200 (Fri, 13 Oct 2017)" );
	script_cve_id( "CVE-2017-13721", "CVE-2017-13723" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-04 02:29:00 +0000 (Sun, 04 Feb 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for xorg-server USN-3453-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-server'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Michal Srb discovered that the X.Org X
  server incorrectly handled shared memory segments. An attacker able to connect
  to an X server, either locally or remotely, could use this issue to crash the
  server, or possibly replace shared memory segments of other X clients in the
  same session. (CVE-2017-13721) Michal Srb discovered that the X.Org X server
  incorrectly handled XKB buffers. An attacker able to connect to an X server,
  either locally or remotely, could use this issue to crash the server, or
  possibly execute arbitrary code. (CVE-2017-13723)" );
	script_tag( name: "affected", value: "xorg-server on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3453-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3453-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "2:1.15.1-0ubuntu2.10", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core-lts-xenial", ver: "2:1.18.3-1ubuntu2.3~trusty3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "2:1.19.3-1ubuntu1.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "2:1.18.4-0ubuntu0.6", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core-hwe-16.04", ver: "2:1.19.3-1ubuntu1~16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

