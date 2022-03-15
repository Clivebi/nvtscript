if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841933" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-08-19 05:58:49 +0200 (Tue, 19 Aug 2014)" );
	script_cve_id( "CVE-2014-0195", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for openssl USN-2232-4" );
	script_tag( name: "affected", value: "openssl on Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "USN-2232-1 fixed vulnerabilities in OpenSSL. One of the patch
backports for Ubuntu 10.04 LTS caused a regression for certain applications.
This update fixes the problem.

We apologize for the inconvenience.

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
	script_xref( name: "USN", value: "2232-4" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2232-4/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libssl0.9.8", ver: "0.9.8k-7ubuntu8.21", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

