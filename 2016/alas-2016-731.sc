if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120720" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-10-26 15:38:19 +0300 (Wed, 26 Oct 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-731)" );
	script_tag( name: "insight", value: "An input-validation flaw was discovered in the Go programming language built in CGI implementation, which set the environment variable HTTP_PROXY using the incoming Proxy HTTP-request header. The environment variable HTTP_PROXY is used by numerous web clients, including Go's net/http package, to specify a proxy server to use for HTTP and, in some cases, HTTPS requests. This meant that when a CGI-based web application ran, an attacker could specify a proxy server which the application then used for subsequent outgoing requests, allowing a man-in-the-middle attack." );
	script_tag( name: "solution", value: "Run yum update golang to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-731.html" );
	script_cve_id( "CVE-2016-5386" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(!isnull( res = isrpmvuln( pkg: "golang-bin", rpm: "golang-bin~1.5.3~1.22.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang", rpm: "golang~1.5.3~1.22.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-docs", rpm: "golang-docs~1.5.3~1.22.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-src", rpm: "golang-src~1.5.3~1.22.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-tests", rpm: "golang-tests~1.5.3~1.22.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "golang-misc", rpm: "golang-misc~1.5.3~1.22.amzn1", rls: "AMAZON" ) )){
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

