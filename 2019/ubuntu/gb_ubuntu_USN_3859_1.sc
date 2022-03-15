if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843871" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2018-1000880", "CVE-2018-1000877", "CVE-2018-1000878", "CVE-2017-14502" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-06 01:15:00 +0000 (Wed, 06 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-01-16 04:01:28 +0100 (Wed, 16 Jan 2019)" );
	script_name( "Ubuntu Update for libarchive USN-3859-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(18\\.10|18\\.04 LTS|16\\.04 LTS|14\\.04 LTS)" );
	script_xref( name: "USN", value: "3859-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3859-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libarchive'
  package(s) announced via the USN-3859-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libarchive incorrectly handled certain archive
files. An attacker could possibly use this issue to cause a denial of
service. CVE-2018-1000880 affected only Ubuntu 18.04 and Ubuntu 18.10
LTS. (CVE-2018-1000877, CVE-2018-1000878, CVE-2018-1000880)

It was discovered that libarchive incorrectly handled certain archive
files. An attacker could possibly use this issue to expose sensitive
information. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04
LTS and Ubuntu 18.04 LTS. (CVE-2017-14502)" );
	script_tag( name: "affected", value: "libarchive on Ubuntu 18.10,
  Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
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
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libarchive13", ver: "3.1.2-7ubuntu2.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libarchive13", ver: "3.2.2-3.1ubuntu0.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "libarchive13", ver: "3.2.2-5ubuntu0.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libarchive13", ver: "3.1.2-11ubuntu0.16.04.5", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

