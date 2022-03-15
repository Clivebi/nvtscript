if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841854" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-17 10:05:28 +0530 (Tue, 17 Jun 2014)" );
	script_cve_id( "CVE-2014-0224", "CVE-2014-0195", "CVE-2014-0221", "CVE-2014-3470" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for openssl USN-2232-2" );
	script_tag( name: "affected", value: "openssl on Ubuntu 14.04 LTS,
  Ubuntu 13.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "USN-2232-1 fixed vulnerabilities in OpenSSL. The upstream fix
for CVE-2014-0224 caused a regression for certain applications that use
tls_session_secret_cb, such as wpa_supplicant. This update fixes the
problem.

Original advisory details:

J&#252 ri Aedla discovered that OpenSSL incorrectly handled invalid DTLS
fragments. A remote attacker could use this issue to cause OpenSSL to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 12.04 LTS, Ubuntu 13.10, and
Ubuntu 14.04 LTS. (CVE-2014-0195)
Imre Rad discovered that OpenSSL incorrectly handled DTLS recursions. A
remote attacker could use this issue to cause OpenSSL to crash, resulting
in a denial of service. (CVE-2014-0221)
KIKUCHI Masashi discovered that OpenSSL incorrectly handled certain
handshakes. A remote attacker could use this flaw to perform a
man-in-the-middle attack and possibly decrypt and modify traffic.
(CVE-2014-0224)
Felix Gr&#246 bert and Ivan Fratri&#263  discovered that OpenSSL incorrectly
handled anonymous ECDH ciphersuites. A remote attacker could use this issue to
cause OpenSSL to crash, resulting in a denial of service. This issue only
affected Ubuntu 12.04 LTS, Ubuntu 13.10, and Ubuntu 14.04 LTS.
(CVE-2014-3470)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2232-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2232-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|13\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1f-1ubuntu2.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1-4ubuntu5.15", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "libssl1.0.0:i386", ver: "1.0.1e-3ubuntu1.5", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

