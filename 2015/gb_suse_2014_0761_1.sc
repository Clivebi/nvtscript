if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850981" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-16 16:03:30 +0200 (Fri, 16 Oct 2015)" );
	script_cve_id( "CVE-2014-0076", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for OpenSSL (SUSE-SU-2014:0761-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'OpenSSL'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL was updated to fix several vulnerabilities:

  * SSL/TLS MITM vulnerability. (CVE-2014-0224)

  * DTLS recursion flaw. (CVE-2014-0221)

  * Anonymous ECDH denial of service. (CVE-2014-3470)

  * Using the FLUSH+RELOAD Cache Side-channel Attack the nonces could
  have been recovered. (CVE-2014-0076)

  Additionally, the following non-security fixes and enhancements have been
  included in this release:

  * Ensure that the stack is marked non-executable on x86 32bit. On
  other processor platforms it was already marked as non-executable
  before. (bnc#870192)

  * IPv6 support was added to the openssl s_client and s_server command
  line tool. (bnc#859228)

  * The openssl command line tool now checks certificates by default
  against /etc/ssl/certs (this can be changed via the -CApath option).
  (bnc#860332)

  * The Elliptic Curve Diffie-Hellman key exchange selector was enabled
  and can be selected by kECDHE, kECDH, ECDH tags in the SSL cipher
  string. (bnc#859924)

  * If an optional openssl1 command line tool is installed in parallel,
  c_rehash uses it to generate certificate hashes in both OpenSSL 0
  and OpenSSL 1 style. This allows parallel usage of OpenSSL 0.9.8j
  and OpenSSL 1.x client libraries with a shared certificate store.
  (bnc#862181)" );
	script_tag( name: "affected", value: "OpenSSL on SUSE Linux Enterprise Server 11 SP2 LTSS, SUSE Linux Enterprise Server 11 SP1 LTSS" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2014:0761-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2|SLES11\\.0SP1)" );
	script_xref( name: "URL", value: "http://www.openssl.org/news/secadv_20140605.txt" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8", rpm: "libopenssl0_9_8~0.9.8j~0.58.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-hmac", rpm: "libopenssl0_9_8-hmac~0.9.8j~0.58.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8j~0.58.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~0.9.8j~0.58.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-32bit", rpm: "libopenssl0_9_8-32bit~0.9.8j~0.58.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-hmac-32bit", rpm: "libopenssl0_9_8-hmac-32bit~0.9.8j~0.58.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8", rpm: "libopenssl0_9_8~0.9.8j~0.58.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-hmac", rpm: "libopenssl0_9_8-hmac~0.9.8j~0.58.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8j~0.58.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~0.9.8j~0.58.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-32bit", rpm: "libopenssl0_9_8-32bit~0.9.8j~0.58.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-hmac-32bit", rpm: "libopenssl0_9_8-hmac-32bit~0.9.8j~0.58.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

