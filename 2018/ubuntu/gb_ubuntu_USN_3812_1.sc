if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843811" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_cve_id( "CVE-2018-16843", "CVE-2018-16844", "CVE-2018-16845" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 17:50:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-11-08 06:01:37 +0100 (Thu, 08 Nov 2018)" );
	script_name( "Ubuntu Update for nginx USN-3812-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|18\\.04 LTS|18\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3812-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3812-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
'nginx' package(s) announced via the USN-3812-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that nginx incorrectly handled
the HTTP/2 implementation. A remote attacker could possibly use this issue to cause
excessive memory consumption, leading to a denial of service. This issue only affected
Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-16843)

Gal Goldshtein discovered that nginx incorrectly handled the HTTP/2
implementation. A remote attacker could possibly use this issue to cause
excessive CPU usage, leading to a denial of service. This issue only
affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 18.10.
(CVE-2018-16844)

It was discovered that nginx incorrectly handled the ngx_http_mp4_module
module. A remote attacker could possibly use this issue with a specially
crafted mp4 file to cause nginx to crash, stop responding, or access
arbitrary memory. (CVE-2018-16845)" );
	script_tag( name: "affected", value: "nginx on Ubuntu 18.10,
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
	if(( res = isdpkgvuln( pkg: "nginx-common", ver: "1.4.6-1ubuntu3.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-core", ver: "1.4.6-1ubuntu3.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-extras", ver: "1.4.6-1ubuntu3.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-full", ver: "1.4.6-1ubuntu3.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-light", ver: "1.4.6-1ubuntu3.9", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "nginx-common", ver: "1.14.0-0ubuntu1.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-core", ver: "1.14.0-0ubuntu1.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-extras", ver: "1.14.0-0ubuntu1.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-full", ver: "1.14.0-0ubuntu1.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-light", ver: "1.14.0-0ubuntu1.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(( res = isdpkgvuln( pkg: "nginx-common", ver: "1.15.5-0ubuntu2.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-core", ver: "1.15.5-0ubuntu2.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-extras", ver: "1.15.5-0ubuntu2.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-full", ver: "1.15.5-0ubuntu2.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-light", ver: "1.15.5-0ubuntu2.1", rls: "UBUNTU18.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "nginx-common", ver: "1.10.3-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-core", ver: "1.10.3-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-extras", ver: "1.10.3-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-full", ver: "1.10.3-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "nginx-light", ver: "1.10.3-0ubuntu0.16.04.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

