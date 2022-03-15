if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120604" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_tag( name: "creation_date", value: "2015-12-15 02:51:18 +0200 (Tue, 15 Dec 2015)" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-614)" );
	script_tag( name: "insight", value: "A NULL pointer dereference flaw was found in the way OpenSSL verified signatures using the RSA PSS algorithm. A remote attacked could possibly use this flaw to crash a TLS/SSL client using OpenSSL, or a TLS/SSL server using OpenSSL if it enabled client authentication. (CVE-2015-3194 )A memory leak vulnerability was found in the way OpenSSL parsed PKCS#7 and CMS data. A remote attacker could use this flaw to cause an application that parses PKCS#7 or CMS data from untrusted sources to use an excessive amount of memory and possibly crash. (CVE-2015-3195 )A race condition flaw, leading to a double free, was found in the way OpenSSL handled pre-shared key (PSK) identify hints. A remote attacker could use this flaw to crash a multi-threaded SSL/TLS client using OpenSSL. (CVE-2015-3196 )" );
	script_tag( name: "solution", value: "Run yum update openssl to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-614.html" );
	script_cve_id( "CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Amazon Linux Local Security Checks" );
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
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "openssl-static", rpm: "openssl-static~1.0.1k~13.88.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-debuginfo", rpm: "openssl-debuginfo~1.0.1k~13.88.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.1k~13.88.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~1.0.1k~13.88.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-perl", rpm: "openssl-perl~1.0.1k~13.88.amzn1", rls: "AMAZON" ) )){
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

