if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843736" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_cve_id( "CVE-2017-1000433" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 21:16:00 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:13:30 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for python-pysaml2 USN-3520-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(17\\.10|17\\.04|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3520-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3520-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-pysaml2'
  package(s) announced via the USN-3520-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that PySAML2 incorrectly accepted any password when
run with python optimizations enabled. An attacker could use this issue
to authenticate as any user without a valid password." );
	script_tag( name: "affected", value: "python-pysaml2 on Ubuntu 17.10,
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
	if(( res = isdpkgvuln( pkg: "python-pysaml2", ver: "3.0.0-3ubuntu2.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-pysaml2", ver: "3.0.0-3ubuntu2.2", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "python-pysaml2", ver: "3.0.0-3ubuntu1.17.04.3", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-pysaml2", ver: "3.0.0-3ubuntu1.17.04.3", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python-pysaml2", ver: "3.0.0-3ubuntu1.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "python3-pysaml2", ver: "3.0.0-3ubuntu1.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

