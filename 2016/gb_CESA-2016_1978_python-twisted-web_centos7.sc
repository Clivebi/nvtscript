if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882568" );
	script_version( "2020-03-18T09:15:45+0000" );
	script_tag( name: "last_modification", value: "2020-03-18 09:15:45 +0000 (Wed, 18 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-10-05 15:43:19 +0530 (Wed, 05 Oct 2016)" );
	script_cve_id( "CVE-2016-1000111" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for python-twisted-web CESA-2016:1978 centos7" );
	script_tag( name: "summary", value: "Check the version of python-twisted-web" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Twisted is an event-based framework for
internet applications. Twisted Web is a complete web server, aimed at hosting
web applications using Twisted and Python, but fully able to serve static pages
too.

Security Fix(es):

  * It was discovered that python-twisted-web used the value of the Proxy
header from HTTP requests to initialize the HTTP_PROXY environment variable
for CGI scripts, which in turn was incorrectly used by certain HTTP client
implementations to configure the proxy for outgoing HTTP requests. A remote
attacker could possibly use this flaw to redirect HTTP requests performed
by a CGI script to an attacker-controlled proxy via a malicious HTTP
request. (CVE-2016-1000111)

Note: After this update, python-twisted-web will no longer pass the value
of the Proxy request header to scripts via the HTTP_PROXY environment
variable.

Red Hat would like to thank Scott Geary (VendHQ) for reporting this issue." );
	script_tag( name: "affected", value: "python-twisted-web on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1978" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-September/022100.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "python-twisted-web", rpm: "python-twisted-web~12.1.0~5.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

