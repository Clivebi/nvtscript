if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843029" );
	script_version( "2021-09-13T13:34:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 13:34:59 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-03 12:10:56 +0530 (Fri, 03 Feb 2017)" );
	script_cve_id( "CVE-2016-2177", "CVE-2016-7055", "CVE-2016-7056", "CVE-2016-8610", "CVE-2017-3731", "CVE-2017-3732" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openssl USN-3181-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Guido Vranken discovered that OpenSSL used undefined behaviour when
performing pointer arithmetic. A remote attacker could possibly use this
issue to cause OpenSSL to crash, resulting in a denial of service. This
issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS as other
releases were fixed in a previous security update. (CVE-2016-2177)

It was discovered that OpenSSL did not properly handle Montgomery
multiplication, resulting in incorrect results leading to transient
failures. This issue only applied to Ubuntu 16.04 LTS, and Ubuntu 16.10.
(CVE-2016-7055)

It was discovered that OpenSSL did not properly use constant-time
operations when performing ECDSA P-256 signing. A remote attacker could
possibly use this issue to perform a timing attack and recover private
ECDSA keys. This issue only applied to Ubuntu 12.04 LTS and Ubuntu 14.04
LTS. (CVE-2016-7056)

Shi Lei discovered that OpenSSL incorrectly handled certain warning alerts.
A remote attacker could possibly use this issue to cause OpenSSL to stop
responding, resulting in a denial of service. (CVE-2016-8610)

Robert &#346 wi&#281 cki discovered that OpenSSL incorrectly handled certain
truncated packets. A remote attacker could possibly use this issue to cause
OpenSSL to crash, resulting in a denial of service. (CVE-2017-3731)

It was discovered that OpenSSL incorrectly performed the x86_64 Montgomery
squaring procedure. While unlikely, a remote attacker could possibly use
this issue to recover private keys. This issue only applied to Ubuntu 16.04
LTS, and Ubuntu 16.10. (CVE-2017-3732)" );
	script_tag( name: "affected", value: "openssl on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3181-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3181-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.10|12\\.04 LTS|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1f-1ubuntu2.22", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.1f-1ubuntu2.22", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.2g-1ubuntu9.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.2g-1ubuntu9.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1-4ubuntu5.39", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.1-4ubuntu5.39", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.2g-1ubuntu4.6", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.2g-1ubuntu4.6", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

