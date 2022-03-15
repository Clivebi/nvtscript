if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850590" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2014-06-09 13:53:36 +0530 (Mon, 09 Jun 2014)" );
	script_cve_id( "CVE-2014-0195", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "openSUSE: Security Advisory for update (openSUSE-SU-2014:0765-1)" );
	script_tag( name: "affected", value: "update on openSUSE 11.4" );
	script_tag( name: "insight", value: "The openssl library was updated to version 1.0.0m fixing various security
  issues and bugs:

  Security issues fixed:

  - CVE-2014-0224: Fix for SSL/TLS MITM flaw. An attacker using a carefully
  crafted handshake can force the use of weak keying material in OpenSSL
  SSL/TLS clients and servers.

  - CVE-2014-0221: Fix DTLS recursion flaw. By sending an invalid DTLS
  handshake to an OpenSSL DTLS client the code can be made to recurse
  eventually crashing in a DoS attack.

  - CVE-2014-0195: Fix DTLS invalid fragment vulnerability. A buffer
  overrun attack can be triggered by sending invalid DTLS fragments to an
  OpenSSL DTLS client or server. This is potentially exploitable to run
  arbitrary code on a vulnerable client or server.

  - CVE-2014-3470: Fix bug in TLS code where clients enable anonymous ECDH
  ciphersuites are subject to a denial of service attack." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "openSUSE-SU", value: "2014:0765-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'update'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE11\\.4" );
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
if(release == "openSUSE11.4"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-devel", rpm: "libopenssl-devel~1.0.0m~18.53.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0", rpm: "libopenssl1_0_0~1.0.0m~18.53.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo", rpm: "libopenssl1_0_0-debuginfo~1.0.0m~18.53.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.0m~18.53.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-debuginfo", rpm: "openssl-debuginfo~1.0.0m~18.53.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-debugsource", rpm: "openssl-debugsource~1.0.0m~18.53.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-32bit", rpm: "libopenssl1_0_0-32bit~1.0.0m~18.53.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo-32bit", rpm: "libopenssl1_0_0-debuginfo-32bit~1.0.0m~18.53.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~1.0.0m~18.53.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo-x86", rpm: "libopenssl1_0_0-debuginfo-x86~1.0.0m~18.53.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-x86", rpm: "libopenssl1_0_0-x86~1.0.0m~18.53.1", rls: "openSUSE11.4" ) )){
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

