if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891301" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-1304", "CVE-2018-1305" );
	script_name( "Debian LTS: Security Advisory for tomcat7 (DLA-1301-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00004.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "tomcat7 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
7.0.28-4+deb7u18.

We recommend that you upgrade your tomcat7 packages." );
	script_tag( name: "summary", value: "Two security vulnerabilities have been discovered in the Tomcat
servlet and JSP engine.

CVE-2018-1304
The URL pattern of '' (the empty string) which exactly maps to the
context root was not correctly handled in Apache Tomcat when used
as part of a security constraint definition. This caused the
constraint to be ignored. It was, therefore, possible for
unauthorized users to gain access to web application resources that
should have been protected. Only security constraints with a URL
pattern of the empty string were affected.

CVE-2018-1305
Security constraints defined by annotations of Servlets in Apache
Tomcat were only applied once a Servlet had been loaded. Because
security constraints defined in this way apply to the URL pattern
and any URLs below that point, it was possible - depending on the
order Servlets were loaded - for some security constraints not to be
applied. This could have exposed resources to users who were not
authorized to access them." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.0-java", ver: "7.0.28-4+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.0-java-doc", ver: "7.0.28-4+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.28-4+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.28-4+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-admin", ver: "7.0.28-4+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-common", ver: "7.0.28-4+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-docs", ver: "7.0.28-4+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-examples", ver: "7.0.28-4+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-user", ver: "7.0.28-4+deb7u18", rls: "DEB7" ) )){
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

