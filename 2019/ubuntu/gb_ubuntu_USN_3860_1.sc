if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843872" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2018-20544", "CVE-2018-20545", "CVE-2018-20548", "CVE-2018-20459", "CVE-2018-20546", "CVE-2018-20547", "CVE-2018-20549" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-05 00:29:00 +0000 (Fri, 05 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-01-16 04:01:39 +0100 (Wed, 16 Jan 2019)" );
	script_name( "Ubuntu Update for libcaca USN-3860-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|18\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3860-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3860-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'libcaca' package(s) announced via the USN-3860-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libcaca incorrectly
  handled certain images. An attacker could possibly use this issue to cause a denial of service.
(CVE-2018-20544)

It was discovered that libcaca incorrectly handled certain images.
An attacker could possibly use this issue to execute arbitrary code.
(CVE-2018-20545, CVE-2018-20548, CVE-2018-20459)

It was discovered that libcaca incorrectly handled certain images.
An attacker could possibly use this issue to access sensitive
information.
(CVE-2018-20546, CVE-2018-20547)" );
	script_tag( name: "affected", value: "libcaca on Ubuntu 18.10,
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
	if(( res = isdpkgvuln( pkg: "caca-utils", ver: "0.99.beta18-1ubuntu5.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcaca0", ver: "0.99.beta18-1ubuntu5.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "caca-utils", ver: "0.99.beta19-2ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcaca0", ver: "0.99.beta19-2ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "caca-utils", ver: "0.99.beta19-2ubuntu0.18.10.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcaca0", ver: "0.99.beta19-2ubuntu0.18.10.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "caca-utils", ver: "0.99.beta19-2ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcaca0", ver: "0.99.beta19-2ubuntu0.16.04.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

