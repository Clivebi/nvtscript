if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892733" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-30640", "CVE-2021-33037" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-26 17:00:00 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-08-06 03:00:23 +0000 (Fri, 06 Aug 2021)" );
	script_name( "Debian LTS: Security Advisory for tomcat8 (DLA-2733-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/08/msg00009.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2733-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2733-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/991046" );
	script_xref( name: "URL", value: "https://bugs.debian.org/991046" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat8'
  package(s) announced via the DLA-2733-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several security vulnerabilities have been discovered in the Tomcat
servlet and JSP engine.

CVE-2021-30640

A vulnerability in the JNDI Realm of Apache Tomcat allows an attacker to
authenticate using variations of a valid user name and/or to bypass some of
the protection provided by the LockOut Realm.

CVE-2021-33037

Apache Tomcat did not correctly parse the HTTP transfer-encoding request
header in some circumstances leading to the possibility to request
smuggling when used with a reverse proxy. Specifically: - Tomcat
incorrectly ignored the transfer encoding header if the client declared it
would only accept an HTTP/1.0 response, - Tomcat honoured the identify
encoding, and - Tomcat did not ensure that, if present, the chunked
encoding was the final encoding." );
	script_tag( name: "affected", value: "'tomcat8' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
8.5.54-0+deb9u7.

We recommend that you upgrade your tomcat8 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.1-java", ver: "8.5.54-0+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.1-java-doc", ver: "8.5.54-0+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat8-embed-java", ver: "8.5.54-0+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.5.54-0+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8", ver: "8.5.54-0+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-admin", ver: "8.5.54-0+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-common", ver: "8.5.54-0+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-docs", ver: "8.5.54-0+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-examples", ver: "8.5.54-0+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-user", ver: "8.5.54-0+deb9u7", rls: "DEB9" ) )){
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

