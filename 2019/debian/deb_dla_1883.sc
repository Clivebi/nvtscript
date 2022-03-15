if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891883" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2016-5388", "CVE-2018-8014", "CVE-2019-0221" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-08-14 02:00:17 +0000 (Wed, 14 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for tomcat8 (DLA-1883-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00015.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1883-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/929895" );
	script_xref( name: "URL", value: "https://bugs.debian.org/898935" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat8'
  package(s) announced via the DLA-1883-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several minor issues have been fixed in tomcat8, a Java Servlet and
JSP engine.

CVE-2016-5388

Apache Tomcat, when the CGI Servlet is enabled, follows RFC 3875
section 4.1.18 and therefore does not protect applications from
the presence of untrusted client data in the HTTP_PROXY
environment variable, which might allow remote attackers to
redirect an application's outbound HTTP traffic to an arbitrary
proxy server via a crafted Proxy header in an HTTP request, aka an
'httpoxy' issue. The 'cgi' servlet now has a 'envHttpHeaders'
parameter to filter environment variables.

CVE-2018-8014

The defaults settings for the CORS filter provided in Apache
Tomcat are insecure and enable 'supportsCredentials' for all
origins. It is expected that users of the CORS filter will have
configured it appropriately for their environment rather than
using it in the default configuration. Therefore, it is expected
that most users will not be impacted by this issue.

CVE-2019-0221

The SSI printenv command in Apache Tomcat echoes user provided
data without escaping and is, therefore, vulnerable to XSS. SSI is
disabled by default. The printenv command is intended for
debugging and is unlikely to be present in a production website." );
	script_tag( name: "affected", value: "'tomcat8' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
8.0.14-1+deb8u15.

We recommend that you upgrade your tomcat8 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.1-java", ver: "8.0.14-1+deb8u15", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.1-java-doc", ver: "8.0.14-1+deb8u15", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.0.14-1+deb8u15", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8", ver: "8.0.14-1+deb8u15", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-admin", ver: "8.0.14-1+deb8u15", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-common", ver: "8.0.14-1+deb8u15", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-docs", ver: "8.0.14-1+deb8u15", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-examples", ver: "8.0.14-1+deb8u15", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-user", ver: "8.0.14-1+deb8u15", rls: "DEB8" ) )){
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

