if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843800" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_cve_id( "CVE-2018-14665" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-22 23:15:00 +0000 (Tue, 22 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-10-27 06:24:24 +0200 (Sat, 27 Oct 2018)" );
	script_name( "Ubuntu Update for xorg-server USN-3802-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|18\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3802-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3802-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-server'
  package(s) announced via the USN-3802-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Narendra Shinde discovered that the X.Org X server incorrectly handled
certain command line parameters when running as root with the legacy
wrapper. When certain graphics drivers are being used, a local attacker
could possibly use this issue to overwrite arbitrary files and escalate
privileges." );
	script_tag( name: "affected", value: "xorg-server on Ubuntu 18.10,
  Ubuntu 18.04 LTS,
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
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "2:1.19.6-1ubuntu4.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "2:1.20.1-3ubuntu2.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "xserver-xorg-core-hwe-16.04", ver: "2:1.19.6-1ubuntu4.1~16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

