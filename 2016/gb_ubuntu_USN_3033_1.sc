if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842832" );
	script_version( "2021-09-20T11:13:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:13:33 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-07-15 05:27:24 +0200 (Fri, 15 Jul 2016)" );
	script_cve_id( "CVE-2015-8916", "CVE-2015-8917", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8930", "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8933", "CVE-2015-8934", "CVE-2016-5844", "CVE-2016-4300", "CVE-2016-4302", "CVE-2016-4809" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libarchive USN-3033-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libarchive'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Hanno B&#246 ck discovered that libarchive
  contained multiple security issues when processing certain malformed archive
  files. A remote attacker could use this issue to cause libarchive to crash,
  resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-8916, CVE-2015-8917 CVE-2015-8919, CVE-2015-8920, CVE-2015-8921,
CVE-2015-8922, CVE-2015-8923, CVE-2015-8924, CVE-2015-8925, CVE-2015-8926,
CVE-2015-8928, CVE-2015-8930, CVE-2015-8931, CVE-2015-8932, CVE-2015-8933,
CVE-2015-8934, CVE-2016-5844)

Marcin 'Icewall' Noga discovered that libarchive contained multiple
security issues when processing certain malformed archive files. A remote
attacker could use this issue to cause libarchive to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2016-4300,
CVE-2016-4302)

It was discovered that libarchive incorrectly handled memory allocation
with large cpio symlinks. A remote attacker could use this issue to
possibly cause libarchive to crash, resulting in a denial of service.
(CVE-2016-4809)" );
	script_tag( name: "affected", value: "libarchive on Ubuntu 16.04 LTS,
  Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3033-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3033-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|16\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libarchive13:i386", ver: "3.1.2-7ubuntu2.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libarchive13:amd64", ver: "3.1.2-7ubuntu2.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libarchive12:i386", ver: "3.0.3-6ubuntu1.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libarchive12:amd64", ver: "3.0.3-6ubuntu1.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libarchive13:i386", ver: "3.1.2-11ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libarchive13:amd64", ver: "3.1.2-11ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libarchive13:i386", ver: "3.1.2-11ubuntu0.15.10.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libarchive13:amd64", ver: "3.1.2-11ubuntu0.15.10.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

