if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842186" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-05-01 05:50:17 +0200 (Fri, 01 May 2015)" );
	script_cve_id( "CVE-2015-3143", "CVE-2015-3144", "CVE-2015-3145", "CVE-2015-3148", "CVE-2015-3153" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for curl USN-2591-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Paras Sethia discovered that curl could
incorrectly re-use NTLM HTTP credentials when subsequently connecting to the
same host over HTTP. (CVE-2015-3143)

Hanno B&#246 ck discovered that curl incorrectly handled zero-length host names.
If a user or automated system were tricked into using a specially crafted
host name, an attacker could possibly use this issue to cause curl to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 14.10 and Ubuntu 15.04.
(CVE-2015-3144)

Hanno B&#246 ck discovered that curl incorrectly handled cookie path elements.
If a user or automated system were tricked into parsing a specially crafted
cookie, an attacker could possibly use this issue to cause curl to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 14.10 and Ubuntu 15.04.
(CVE-2015-3145)

Isaac Boukris discovered that when using Negotiate authenticated
connections, curl could incorrectly authenticate the entire connection and
not just specific HTTP requests. (CVE-2015-3148)

Yehezkel Horowitz and Oren Souroujon discovered that curl sent HTTP headers
both to servers and proxies by default, contrary to expectations. This
issue only affected Ubuntu 14.10 and Ubuntu 15.04. (CVE-2015-3153)" );
	script_tag( name: "affected", value: "curl on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2591-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2591-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS|12\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "libcurl3:amd64", ver: "7.37.1-1ubuntu3.4", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3:i386", ver: "7.37.1-1ubuntu3.4", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls:amd64", ver: "7.37.1-1ubuntu3.4", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls:i386", ver: "7.37.1-1ubuntu3.4", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss:amd64", ver: "7.37.1-1ubuntu3.4", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss:i386", ver: "7.37.1-1ubuntu3.4", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libcurl3:i386", ver: "7.35.0-1ubuntu2.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3:amd64", ver: "7.35.0-1ubuntu2.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls:i386", ver: "7.35.0-1ubuntu2.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls:amd64", ver: "7.35.0-1ubuntu2.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss:amd64", ver: "7.35.0-1ubuntu2.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss:i386", ver: "7.35.0-1ubuntu2.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.22.0-3ubuntu4.14", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.22.0-3ubuntu4.14", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.22.0-3ubuntu4.14", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

