if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842242" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-12 06:09:14 +0200 (Fri, 12 Jun 2015)" );
	script_cve_id( "CVE-2014-8176", "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for openssl USN-2639-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Praveen Kariyanahalli, Ivan Fratric and
Felix Groebert discovered that OpenSSL incorrectly handled memory when buffering
DTLS data. A remote attacker could use this issue to cause OpenSSL to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2014-8176)

Joseph Barr-Pixton discovered that OpenSSL incorrectly handled malformed
ECParameters structures. A remote attacker could use this issue to cause
OpenSSL to hang, resulting in a denial of service. (CVE-2015-1788)

Robert Swiecki and Hanno B&#246 ck discovered that OpenSSL incorrectly handled
certain ASN1_TIME strings. A remote attacker could use this issue to cause
OpenSSL to crash, resulting in a denial of service. (CVE-2015-1789)

Michal Zalewski discovered that OpenSSL incorrectly handled missing content
when parsing ASN.1-encoded PKCS#7 blobs. A remote attacker could use this
issue to cause OpenSSL to crash, resulting in a denial of service.
(CVE-2015-1790)

Emilia K&#228 sper discovered that OpenSSL incorrectly handled NewSessionTicket
when being used by a multi-threaded client. A remote attacker could use
this issue to cause OpenSSL to crash, resulting in a denial of service.
(CVE-2015-1791)

Johannes Bauer discovered that OpenSSL incorrectly handled verifying
signedData messages using the CMS code. A remote attacker could use this
issue to cause OpenSSL to hang, resulting in a denial of service.
(CVE-2015-1792)

As a security improvement, this update also modifies OpenSSL behaviour to
reject DH key sizes below 768 bits, preventing a possible downgrade
attack." );
	script_tag( name: "affected", value: "openssl on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2639-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2639-1/" );
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
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.1f-1ubuntu9.8", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1f-1ubuntu9.8", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:amd64", ver: "1.0.1f-1ubuntu2.15", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1f-1ubuntu2.15", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1-4ubuntu5.31", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

