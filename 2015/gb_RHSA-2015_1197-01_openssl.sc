if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871385" );
	script_version( "$Revision: 12497 $" );
	script_cve_id( "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-4000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-07-01 06:28:09 +0200 (Wed, 01 Jul 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for openssl RHSA-2015:1197-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

An out-of-bounds read flaw was found in the X509_cmp_time() function of
OpenSSL. A specially crafted X.509 certificate or a Certificate Revocation
List (CRL) could possibly cause a TLS/SSL server or client using OpenSSL
to crash. (CVE-2015-1789)

A NULL pointer dereference was found in the way OpenSSL handled certain
PKCS#7 inputs. A specially crafted PKCS#7 input with missing
EncryptedContent data could cause an application using OpenSSL to crash.
(CVE-2015-1790)

A flaw was found in the way the TLS protocol composes the Diffie-Hellman
(DH) key exchange. A man-in-the-middle attacker could use this flaw to
force the use of weak 512 bit export-grade keys during the key exchange,
allowing them to decrypt all traffic. (CVE-2015-4000)

Note: This update forces the TLS/SSL client implementation in OpenSSL to
reject DH key sizes below 768 bits, which prevents sessions to be
downgraded to export-grade keys. Future updates may raise this limit to
1024 bits.

Red Hat would like to thank the OpenSSL project for reporting CVE-2015-1789
and CVE-2015-1790. Upstream acknowledges Robert Swiecki and Hanno Bock as
the original reporters of CVE-2015-1789, and Michal Zalewski as the
original reporter of CVE-2015-1790.

All openssl users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. For the update to take
effect, all services linked to the OpenSSL library must be restarted, or
the system rebooted." );
	script_tag( name: "affected", value: "openssl on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2015:1197-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2015-June/msg00042.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8e~36.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-debuginfo", rpm: "openssl-debuginfo~0.9.8e~36.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~0.9.8e~36.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-perl", rpm: "openssl-perl~0.9.8e~36.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

