if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882198" );
	script_version( "$Revision: 14058 $" );
	script_cve_id( "CVE-2014-8176", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-3216" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-16 06:13:40 +0200 (Tue, 16 Jun 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for openssl CESA-2015:1115 centos6" );
	script_tag( name: "summary", value: "Check the version of openssl" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL is a toolkit that implements the
  Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

An invalid free flaw was found in the way OpenSSL handled certain DTLS
handshake messages. A malicious DTLS client or server could cause a DTLS
server or client using OpenSSL to crash or, potentially, execute arbitrary
code. (CVE-2014-8176)

A flaw was found in the way the OpenSSL packages shipped with Red Hat
Enterprise Linux 6 and 7 performed locking in the ssleay_rand_bytes()
function. This issue could possibly cause a multi-threaded application
using OpenSSL to perform an out-of-bounds read and crash. (CVE-2015-3216)

An out-of-bounds read flaw was found in the X509_cmp_time() function of
OpenSSL. A specially crafted X.509 certificate or a Certificate Revocation
List (CRL) could possibly cause a TLS/SSL server or client using OpenSSL
to crash. (CVE-2015-1789)

A race condition was found in the session handling code of OpenSSL. This
issue could possibly cause a multi-threaded TLS/SSL client using OpenSSL
to double free session ticket data and crash. (CVE-2015-1791)

A flaw was found in the way OpenSSL handled Cryptographic Message Syntax
(CMS) messages. A CMS message with an unknown hash function identifier
could cause an application using OpenSSL to enter an infinite loop.
(CVE-2015-1792)

A NULL pointer dereference was found in the way OpenSSL handled certain
PKCS#7 inputs. A specially crafted PKCS#7 input with missing
EncryptedContent data could cause an application using OpenSSL to crash.
(CVE-2015-1790)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2014-8176, CVE-2015-1789, CVE-2015-1790, CVE-2015-1791 and
CVE-2015-1792 flaws. Upstream acknowledges Praveen Kariyanahalli and Ivan
Fratric as the original reporters of CVE-2014-8176, Robert Swiecki and
Hanno Bck as the original reporters of CVE-2015-1789, Michal Zalewski as
the original reporter of CVE-2015-1790, Emilia Ksper as the original
report of  CVE-2015-1791 and Johannes Bauer as the original reporter of
CVE-2015-1792.

All openssl users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. For the update to take
effect, all services linked to the OpenSSL library must be restarted, or
the system rebooted." );
	script_tag( name: "affected", value: "openssl on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1115" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-June/021173.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.1e~30.el6.11", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~1.0.1e~30.el6.11", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-perl", rpm: "openssl-perl~1.0.1e~30.el6.11", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-static", rpm: "openssl-static~1.0.1e~30.el6.11", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

