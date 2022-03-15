if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704673" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2019-17569", "CVE-2020-1935", "CVE-2020-1938" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-05-05 03:00:07 +0000 (Tue, 05 May 2020)" );
	script_name( "Debian: Security Advisory for tomcat8 (DSA-4673-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4673.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4673-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat8'
  package(s) announced via the DSA-4673-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the Tomcat servlet and JSP
engine, which could result in HTTP request smuggling and code execution
in the AJP connector (disabled by default in Debian)." );
	script_tag( name: "affected", value: "'tomcat8' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), these problems have been fixed
in version 8.5.54-0+deb9u1.

We recommend that you upgrade your tomcat8 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.1-java", ver: "8.5.54-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.1-java-doc", ver: "8.5.54-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat8-embed-java", ver: "8.5.54-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.5.54-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8", ver: "8.5.54-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-admin", ver: "8.5.54-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-common", ver: "8.5.54-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-docs", ver: "8.5.54-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-examples", ver: "8.5.54-0+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-user", ver: "8.5.54-0+deb9u1", rls: "DEB9" ) )){
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

