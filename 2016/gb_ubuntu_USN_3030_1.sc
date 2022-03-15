if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842827" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-07-12 05:25:44 +0200 (Tue, 12 Jul 2016)" );
	script_cve_id( "CVE-2013-7456", "CVE-2016-5116", "CVE-2016-5766", "CVE-2016-6128", "CVE-2016-6161" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libgd2 USN-3030-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgd2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the GD library
  incorrectly handled memory when using gdImageScaleTwoPass(). A remote attacker
  could possibly use this issue to cause a denial of service. This issue only
  affected Ubuntu 14.04 LTS. (CVE-2013-7456)

  It was discovered that the GD library incorrectly handled certain malformed
  XBM images. If a user or automated system were tricked into processing a
  specially crafted XBM image, an attacker could cause a denial of service.
  This issue only affected Ubuntu 14.04 LTS, Ubuntu 15.10 and Ubuntu 16.04
  LTS. (CVE-2016-5116)

  It was discovered that the GD library incorrectly handled memory when using
  _gd2GetHeader(). A remote attacker could possibly use this issue to cause a
  denial of service or possibly execute arbitrary code. (CVE-2016-5766)

  It was discovered that the GD library incorrectly handled certain color
  indexes. A remote attacker could possibly use this issue to cause a denial
  of service. This issue only affected Ubuntu 14.04 LTS, Ubuntu 15.10 and
  Ubuntu 16.04 LTS. (CVE-2016-6128)

  It was discovered that the GD library incorrectly handled memory when
  encoding a GIF image. A remote attacker could possibly use this issue to
  cause a denial of service. (CVE-2016-6161)" );
	script_tag( name: "affected", value: "libgd2 on Ubuntu 16.04 LTS,
  Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3030-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3030-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.04 LTS|15\\.10|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libgd3:i386", ver: "2.1.0-3ubuntu0.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgd3:amd64", ver: "2.1.0-3ubuntu0.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgd3:i386", ver: "2.1.1-4ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgd3:amd64", ver: "2.1.1-4ubuntu0.16.04.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libgd3:i386", ver: "2.1.1-4ubuntu0.15.10.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgd3:amd64", ver: "2.1.1-4ubuntu0.15.10.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgd2-noxpm", ver: "2.0.36~rc1~dfsg-6ubuntu2.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgd2-xpm", ver: "2.0.36~rc1~dfsg-6ubuntu2.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

