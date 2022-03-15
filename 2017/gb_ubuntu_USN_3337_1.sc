if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843223" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-22 07:12:36 +0200 (Thu, 22 Jun 2017)" );
	script_cve_id( "CVE-2016-2226", "CVE-2016-4487", "CVE-2016-4488", "CVE-2016-4489", "CVE-2016-4490", "CVE-2016-4491", "CVE-2016-4492", "CVE-2016-4493", "CVE-2016-6131" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-12 01:29:00 +0000 (Sat, 12 Aug 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for valgrind USN-3337-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'valgrind'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Valgrind incorrectly
  handled certain string operations. If a user or automated system were tricked
  into processing a specially crafted binary, a remote attacker could possibly
  execute arbitrary code. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04
  LTS and Ubuntu 16.10. (CVE-2016-2226) It was discovered that Valgrind
  incorrectly handled parsing certain binaries. If a user or automated system were
  tricked into processing a specially crafted binary, a remote attacker could use
  this issue to cause Valgrind to crash, resulting in a denial of service.
  (CVE-2016-4487, CVE-2016-4488, CVE-2016-4489, CVE-2016-4490, CVE-2016-4491,
  CVE-2016-4492, CVE-2016-4493, CVE-2016-6131)" );
	script_tag( name: "affected", value: "valgrind on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3337-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3337-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "valgrind", ver: "1:3.10.1-1ubuntu3~14.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "valgrind", ver: "1:3.12.0-1ubuntu1.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "valgrind", ver: "1:3.12.0~svn20160714-1ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "valgrind", ver: "1:3.11.0-1ubuntu4.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

