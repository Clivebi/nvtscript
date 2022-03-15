if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843756" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_cve_id( "CVE-2018-1000007", "CVE-2018-1000005" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-18 22:15:00 +0000 (Tue, 18 Jun 2019)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:15:38 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for curl USN-3554-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3554-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3554-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the USN-3554-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that curl incorrectly handled certain data. An
attacker could possibly use this to cause a denial of service or even
to get access to sensitive data. This issue only affected Ubuntu 16.04
LTS and Ubuntu 17.10.

It was discovered that curl could accidentally leak authentication
data. An attacker could possibly use this to get access to sensitive
information. (CVE-2018-1000007)" );
	script_tag( name: "affected", value: "curl on Ubuntu 17.10,
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
	if(( res = isdpkgvuln( pkg: "curl", ver: "7.35.0-1ubuntu2.14", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.35.0-1ubuntu2.14", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.35.0-1ubuntu2.14", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.35.0-1ubuntu2.14", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "curl", ver: "7.55.1-1ubuntu2.3", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.55.1-1ubuntu2.3", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.55.1-1ubuntu2.3", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.55.1-1ubuntu2.3", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "curl", ver: "7.47.0-1ubuntu2.6", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.47.0-1ubuntu2.6", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.47.0-1ubuntu2.6", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.47.0-1ubuntu2.6", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

