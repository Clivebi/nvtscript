if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851220" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-03-08 12:37:39 +0530 (Tue, 08 Mar 2016)" );
	script_cve_id( "CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799", "CVE-2016-0800" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for openssl (openSUSE-SU-2016:0627-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssl fixes the following issues:

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

  Please also note that we built the 13.2 openSUSE openssl already with
  'no-ssl2'.

  * Disable all weak EXPORT ciphers by default. These can be re-enabled if
  required by old legacy software using the environment variable
  'OPENSSL_ALLOW_EXPORT'.

  - CVE-2016-0702 aka the 'CacheBleed' attack. (bsc#968050) Various changes
  in the modular exponentiation code were added that make sure that it is
  not possible to recover RSA secret keys by analyzing cache-bank
  conflicts on the Intel Sandy-Bridge microarchitecture.

  Note that this was only exploitable if the malicious code was running
  on the same hyper threaded Intel Sandy Bridge processor as the victim
  thread performing decryptions.

  - CVE-2016-0705 (bnc#968047): A double free() bug in the DSA ASN1 parser
  code was fixed that could be abused to facilitate a denial-of-service
  attack.

  - CVE-2016-0797 (bnc#968048): The BN_hex2bn() and BN_dec2bn() functions
  had a bug that could result in an attempt to de-reference a NULL pointer
  leading to crashes. This could have security consequences if these
  functions were ever called by user applications with large untrusted
  hex/decimal data. Also, internal usage of these functions in OpenSSL
  uses data from config files or application command line arguments. If
  user developed applications generated config file data based on
  untrusted data, then this could have had security consequences as well.

  - CVE-2016-0798 (bnc#968265) The SRP user database lookup method
  SRP_VBASE_get_by_user() had a memory leak that attackers could abuse to
  facility DoS attacks. To mitigate the issue, the seed handling in
  SRP_VBASE_get_by_user() was disabled even if the user has configured a
  seed. Applications are advised to

  - We're unaffected by CVE-2016-0799 (boo#968374) because we use glibc's
  printf implementation instead of the built in one

  Bugs fixed:

  - avoid running OPENSSL_config twice. This avoids breaking engine loading.
  (boo#952871)" );
	script_tag( name: "affected", value: "openssl on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:0627-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-devel", rpm: "libopenssl-devel~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0", rpm: "libopenssl1_0_0~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo", rpm: "libopenssl1_0_0-debuginfo~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-hmac", rpm: "libopenssl1_0_0-hmac~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-debuginfo", rpm: "openssl-debuginfo~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-debugsource", rpm: "openssl-debugsource~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-devel-32bit", rpm: "libopenssl-devel-32bit~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-32bit", rpm: "libopenssl1_0_0-32bit~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo-32bit", rpm: "libopenssl1_0_0-debuginfo-32bit~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-hmac-32bit", rpm: "libopenssl1_0_0-hmac-32bit~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~1.0.1k~2.33.1", rls: "openSUSE13.2" ) )){
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

