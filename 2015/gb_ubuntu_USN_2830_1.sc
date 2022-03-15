if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842552" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-08 10:53:48 +0100 (Tue, 08 Dec 2015)" );
	script_cve_id( "CVE-2015-1794", "CVE-2015-3193", "CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openssl USN-2830-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Guy Leaver discovered that OpenSSL
incorrectly handled a ServerKeyExchange for an anonymous DH ciphersuite with the
value of p set to 0. A remote attacker could possibly use this issue to cause OpenSSL
to crash, resulting in a denial of service. This issue only applied to Ubuntu 15.10.
(CVE-2015-1794)

Hanno B&#246 ck discovered that the OpenSSL Montgomery squaring procedure
algorithm may produce incorrect results when being used on x86_64. A remote
attacker could possibly use this issue to break encryption. This issue only
applied to Ubuntu 15.10. (CVE-2015-3193)

Lo&#239 c Jonas Etienne discovered that OpenSSL incorrectly handled ASN.1
signatures with a missing PSS parameter. A remote attacker could possibly
use this issue to cause OpenSSL to crash, resulting in a denial of service.
(CVE-2015-3194)

Adam Langley discovered that OpenSSL incorrectly handled malformed
X509_ATTRIBUTE structures. A remote attacker could possibly use this issue
to cause OpenSSL to consume resources, resulting in a denial of service.
(CVE-2015-3195)

It was discovered that OpenSSL incorrectly handled PSK identity hints. A
remote attacker could possibly use this issue to cause OpenSSL to crash,
resulting in a denial of service. This issue only applied to Ubuntu 12.04
LTS, Ubuntu 14.04 LTS and Ubuntu 15.04. (CVE-2015-3196)" );
	script_tag( name: "affected", value: "openssl on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2830-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2830-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|12\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.04"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.1f-1ubuntu11.5", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1f-1ubuntu11.5", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.1f-1ubuntu2.16", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1f-1ubuntu2.16", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1-4ubuntu5.32", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.2d-0ubuntu1.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.2d-0ubuntu1.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

