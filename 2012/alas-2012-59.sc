if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120418" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:25:55 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2012-59)" );
	script_tag( name: "insight", value: "A flaw was found in the way GnuTLS decrypted malformed TLS records. This could cause a TLS/SSL client or server to crash when processing a specially-crafted TLS record from a remote TLS/SSL connection peer. (CVE-2012-1573 )A boundary error was found in the gnutls_session_get_data() function. A malicious TLS/SSL server could use this flaw to crash a TLS/SSL client or, possibly, execute arbitrary code as the client, if the client passed a fixed-sized buffer to gnutls_session_get_data() before checking the real size of the session data provided by the server. (CVE-2011-4128 )" );
	script_tag( name: "solution", value: "Run yum update gnutls to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2012-59.html" );
	script_cve_id( "CVE-2011-4128", "CVE-2012-1573" );
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
	if(!isnull( res = isrpmvuln( pkg: "gnutls-debuginfo", rpm: "gnutls-debuginfo~2.8.5~4.6.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-guile", rpm: "gnutls-guile~2.8.5~4.6.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-utils", rpm: "gnutls-utils~2.8.5~4.6.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-devel", rpm: "gnutls-devel~2.8.5~4.6.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~2.8.5~4.6.amzn1", rls: "AMAZON" ) )){
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

