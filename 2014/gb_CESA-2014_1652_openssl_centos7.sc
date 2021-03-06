if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882062" );
	script_version( "$Revision: 14095 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-11 14:54:56 +0100 (Mon, 11 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-10-17 05:58:44 +0200 (Fri, 17 Oct 2014)" );
	script_cve_id( "CVE-2014-3513", "CVE-2014-3567", "CVE-2014-3566" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_name( "CentOS Update for openssl CESA-2014:1652 centos7" );
	script_tag( name: "summary", value: "Check the version of openssl" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL is a toolkit that implements the
Secure Sockets Layer (SSL), Transport Layer Security (TLS), and Datagram Transport
Layer Security (DTLS) protocols, as well as a full-strength, general purpose
cryptography library.

This update adds support for the TLS Fallback Signaling Cipher Suite Value
(TLS_FALLBACK_SCSV), which can be used to prevent protocol downgrade
attacks against applications which re-connect using a lower SSL/TLS
protocol version when the initial connection indicating the highest
supported protocol version fails.

This can prevent a forceful downgrade of the communication to SSL 3.0.
The SSL 3.0 protocol was found to be vulnerable to the padding oracle
attack when using block cipher suites in cipher block chaining (CBC) mode.
This issue is identified as CVE-2014-3566, and also known under the alias
POODLE. This SSL 3.0 protocol flaw will not be addressed in a future
update  it is recommended that users configure their applications to
require at least TLS protocol version 1.0 for secure communication.

For additional information about this flaw, see the linked Knowledgebase article.

A memory leak flaw was found in the way OpenSSL parsed the DTLS Secure
Real-time Transport Protocol (SRTP) extension data. A remote attacker could
send multiple specially crafted handshake messages to exhaust all available
memory of an SSL/TLS or DTLS server. (CVE-2014-3513)

A memory leak flaw was found in the way an OpenSSL handled failed session
ticket integrity checks. A remote attacker could exhaust all available
memory of an SSL/TLS or DTLS server by sending a large number of invalid
session tickets to that server. (CVE-2014-3567)

All OpenSSL users are advised to upgrade to these updated packages, which
contain backported patches to mitigate the CVE-2014-3566 issue and correct
the CVE-2014-3513 and CVE-2014-3567 issues. For the update to take effect,
all services linked to the OpenSSL library (such as httpd and other
SSL-enabled services) must be restarted or the system rebooted." );
	script_tag( name: "affected", value: "openssl on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:1652" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-October/020695.html" );
	script_xref( name: "URL", value: "https://access.redhat.com/articles/1232123" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.1e~34.el7_0.6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~1.0.1e~34.el7_0.6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-libs", rpm: "openssl-libs~1.0.1e~34.el7_0.6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-perl", rpm: "openssl-perl~1.0.1e~34.el7_0.6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-static", rpm: "openssl-static~1.0.1e~34.el7_0.6", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

