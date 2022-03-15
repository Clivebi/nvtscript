if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843328" );
	script_version( "2021-09-13T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 13:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-11 09:57:05 +0200 (Wed, 11 Oct 2017)" );
	script_cve_id( "CVE-2016-9586", "CVE-2017-1000100", "CVE-2017-1000101", "CVE-2017-1000254", "CVE-2017-7407" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for curl USN-3441-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Daniel Stenberg discovered that curl
  incorrectly handled large floating point output. A remote attacker could use
  this issue to cause curl to crash, resulting in a denial of service, or possibly
  execute arbitrary code. This issue only affected Ubuntu 14.04 LTS and Ubuntu
  16.04 LTS. (CVE-2016-9586) Even Rouault discovered that curl incorrectly handled
  large file names when doing TFTP transfers. A remote attacker could use this
  issue to cause curl to crash, resulting in a denial of service, or possibly
  obtain sensitive memory contents. (CVE-2017-1000100) Brian Carpenter and Yongji
  Ouyang discovered that curl incorrectly handled numerical range globbing. A
  remote attacker could use this issue to cause curl to crash, resulting in a
  denial of service, or possibly obtain sensitive memory contents.
  (CVE-2017-1000101) Max Dymond discovered that curl incorrectly handled FTP PWD
  responses. A remote attacker could use this issue to cause curl to crash,
  resulting in a denial of service. (CVE-2017-1000254) Brian Carpenter discovered
  that curl incorrectly handled the --write-out command line option. A local
  attacker could possibly use this issue to obtain sensitive memory contents.
  (CVE-2017-7407)" );
	script_tag( name: "affected", value: "curl on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3441-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3441-1/" );
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
	if(( res = isdpkgvuln( pkg: "curl", ver: "7.35.0-1ubuntu2.11", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3:amd64", ver: "7.35.0-1ubuntu2.11", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls:amd64", ver: "7.35.0-1ubuntu2.11", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss:amd64", ver: "7.35.0-1ubuntu2.11", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "curl", ver: "7.52.1-4ubuntu1.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3:amd64", ver: "7.52.1-4ubuntu1.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3:i386", ver: "7.52.1-4ubuntu1.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls:amd64", ver: "7.52.1-4ubuntu1.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls:i386", ver: "7.52.1-4ubuntu1.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss:amd64", ver: "7.52.1-4ubuntu1.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss:i386", ver: "7.52.1-4ubuntu1.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "curl", ver: "7.47.0-1ubuntu2.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3:amd64", ver: "7.47.0-1ubuntu2.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3:i386", ver: "7.47.0-1ubuntu2.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls:amd64", ver: "7.47.0-1ubuntu2.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls:i386", ver: "7.47.0-1ubuntu2.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss:amd64", ver: "7.47.0-1ubuntu2.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss:i386", ver: "7.47.0-1ubuntu2.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

