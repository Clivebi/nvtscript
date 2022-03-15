if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850905" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-16 13:54:15 +0200 (Fri, 16 Oct 2015)" );
	script_cve_id( "CVE-2009-5146", "CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for compat-openssl098 (SUSE-SU-2015:0553-2)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'compat-openssl098'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL was updated to fix various security issues.

  The following security issues were fixed:

  - CVE-2015-0209: A Use After Free following d2i_ECPrivatekey error was
  fixed which could lead to crashes for attacker supplied Elliptic Curve
  keys. This could be exploited over SSL connections with client supplied
  keys.

  - CVE-2015-0286: A segmentation fault in ASN1_TYPE_cmp was fixed that
  could be exploited by attackers when e.g. client authentication is used.
  This could be exploited over SSL connections.

  - CVE-2015-0287: A ASN.1 structure reuse memory corruption was fixed. This
  problem can not be exploited over regular SSL connections, only if
  specific client programs use specific ASN.1 routines.

  - CVE-2015-0288: A X509_to_X509_REQ NULL pointer dereference was fixed,
  which could lead to crashes. This function is not commonly used, and not
  reachable over SSL methods.

  - CVE-2015-0289: Several PKCS7 NULL pointer dereferences were fixed, which
  could lead to crashes of programs using the PKCS7 APIs. The SSL apis do
  not use those by default.

  - CVE-2015-0292: Various issues in base64 decoding were fixed, which could
  lead to crashes with memory corruption, for instance by using attacker
  supplied PEM data.

  - CVE-2015-0293: Denial of service via reachable assert in SSLv2 servers,
  could be used by remote attackers to terminate the server process. Note
  that this requires SSLv2 being allowed, which is not the default.

  - CVE-2009-5146: A memory leak in the TLS hostname extension was fixed,
  which could be used by remote attackers to run SSL services out of
  memory." );
	script_tag( name: "affected", value: "compat-openssl098 on SUSE Linux Enterprise Desktop 12" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2015:0553-2" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLED12\\.0SP0" );
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
if(release == "SLED12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "compat-openssl098-debugsource", rpm: "compat-openssl098-debugsource~0.9.8j~73.2", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8", rpm: "libopenssl0_9_8~0.9.8j~73.2", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-32bit", rpm: "libopenssl0_9_8-32bit~0.9.8j~73.2", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-debuginfo", rpm: "libopenssl0_9_8-debuginfo~0.9.8j~73.2", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-debuginfo-32bit", rpm: "libopenssl0_9_8-debuginfo-32bit~0.9.8j~73.2", rls: "SLED12.0SP0" ) )){
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

