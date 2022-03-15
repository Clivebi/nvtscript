if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120187" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:19:29 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-427)" );
	script_tag( name: "insight", value: "A memory leak flaw was found in the way OpenSSL parsed the DTLS Secure Real-time Transport Protocol (SRTP) extension data. A remote attacker could send multiple specially crafted handshake messages to exhaust all available memory of an SSL/TLS or DTLS server.  (CVE-2014-3513 )A memory leak flaw was found in the way an OpenSSL handled failed session ticket integrity checks. A remote attacker could exhaust all available memory of an SSL/TLS or DTLS server by sending a large number of invalid session tickets to that server.  (CVE-2014-3567 )When OpenSSL is configured with no-ssl3 as a build option, servers could accept and complete a SSL 3.0 handshake, and clients could beconfigured to send them.  (CVE-2014-3568 )" );
	script_tag( name: "solution", value: "Run yum update openssl to update your system.  Note that you may need to run yum clean all first." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-427.html" );
	script_cve_id( "CVE-2014-3513", "CVE-2014-3568", "CVE-2014-3567" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.1j~1.80.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-debuginfo", rpm: "openssl-debuginfo~1.0.1j~1.80.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~1.0.1j~1.80.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-static", rpm: "openssl-static~1.0.1j~1.80.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-perl", rpm: "openssl-perl~1.0.1j~1.80.amzn1", rls: "AMAZON" ) )){
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

