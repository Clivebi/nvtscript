if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843733" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_cve_id( "CVE-2016-10209", "CVE-2016-10349", "CVE-2016-10350", "CVE-2017-14166", "CVE-2017-14501", "CVE-2017-14503" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-28 16:29:00 +0000 (Fri, 28 Dec 2018)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:12:58 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for libarchive USN-3736-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3736-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3736-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libarchive'
  package(s) announced via the USN-3736-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libarchive incorrectly handled certain archive
files. A remote attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 14.04 LTS and Ubuntu
16.04 LTS. (CVE-2016-10209, CVE-2016-10349, CVE-2016-10350)

Agostino Sarubbo discovered that libarchive incorrectly handled certain
XAR files. A remote attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 14.04 LTS and Ubuntu
16.04 LTS. (CVE-2017-14166)

It was discovered that libarchive incorrectly handled certain files.
A remote attacker could possibly use this issue to get access to
sensitive information. (CVE-2017-14501, CVE-2017-14503)" );
	script_tag( name: "affected", value: "libarchive on Ubuntu 18.04 LTS,
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
	if(( res = isdpkgvuln( pkg: "libarchive13", ver: "3.1.2-7ubuntu2.6", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libarchive13", ver: "3.2.2-3.1ubuntu0.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libarchive13", ver: "3.1.2-11ubuntu0.16.04.4", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

