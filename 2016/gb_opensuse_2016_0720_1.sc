if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851228" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-03-12 06:13:13 +0100 (Sat, 12 Mar 2016)" );
	script_cve_id( "CVE-2015-3197", "CVE-2016-0702", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0797", "CVE-2016-0799", "CVE-2016-0800", "CVE-2015-0293" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for openssl (openSUSE-SU-2016:0720-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for compat-openssl098 fixes various security issues and bugs:

  Security issues fixed:

  - CVE-2016-0800 aka the 'DROWN' attack (bsc#968046): OpenSSL was
  vulnerable to a cross-protocol attack that could lead to decryption of
  TLS sessions by using a server supporting SSLv2 and EXPORT cipher suites
  as a Bleichenbacher RSA padding oracle.

  This update changes the openssl library to:

  * Disable SSLv2 protocol support by default.

  This can be overridden by setting the environment variable
  'OPENSSL_ALLOW_SSL2' or by using SSL_CTX_clear_options using the
  SSL_OP_NO_SSLv2 flag.

  Note that various services and clients had already disabled SSL
  protocol 2 by default previously.

  * Disable all weak EXPORT ciphers by default. These can be re-enabled if
  required by old legacy software using the environment variable
  'OPENSSL_ALLOW_EXPORT'.

  - CVE-2016-0797 (bnc#968048): The BN_hex2bn() and BN_dec2bn() functions
  had a bug that could result in an attempt to de-reference a NULL pointer
  leading to crashes. This could have security consequences if these
  functions were ever called by user applications with large untrusted
  hex/decimal data. Also, internal usage of these functions in OpenSSL
  uses data from config files
  or application command line arguments. If user developed applications
  generated config file data based on untrusted data, then this could
  have had security consequences as well.

  - CVE-2016-0799 (bnc#968374) On many 64 bit systems, the internal fmtstr()
  and doapr_outch() functions could miscalculate the length of a string
  and attempt to access out-of-bounds memory locations. These problems
  could have enabled attacks where large amounts of untrusted data is
  passed to the BIO_*printf functions. If applications use these functions
  in this way then they could have been vulnerable. OpenSSL itself uses
  these functions when printing out human-readable dumps of ASN.1 data.
  Therefore applications that print this data could have been vulnerable
  if the data is from untrusted sources. OpenSSL command line applications
  could also have been vulnerable when they print out ASN.1 data, or if
  untrusted data is passed as command line arguments. Libssl is not
  considered directly vulnerable.

  - CVE-2015-3197 (bsc#963415): The SSLv2 protocol did not block disabled
  ciphers.

  Note that the March 1st 2016 release also references following CVEs that
  were fixed by us with CVE-2015-0293 in 2015:

  - CVE-2016-0703 (bsc#968051): This issue only affected versions of OpenSSL
  prior to March 19th 2015 at which time the code was refactor ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "openssl on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:0720-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "compat-openssl098-debugsource", rpm: "compat-openssl098-debugsource~0.9.8j~9.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8", rpm: "libopenssl0_9_8~0.9.8j~9.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-debuginfo", rpm: "libopenssl0_9_8-debuginfo~0.9.8j~9.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-32bit", rpm: "libopenssl0_9_8-32bit~0.9.8j~9.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-debuginfo-32bit", rpm: "libopenssl0_9_8-debuginfo-32bit~0.9.8j~9.1", rls: "openSUSELeap42.1" ) )){
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

