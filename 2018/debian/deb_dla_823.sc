if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890823" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2017-6056" );
	script_name( "Debian LTS: Security Advisory for tomcat7 (DLA-823-2)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-05 00:00:00 +0100 (Fri, 05 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/02/msg00022.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "tomcat7 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
7.0.28-4+deb7u11.

We recommend that you upgrade your tomcat7 packages." );
	script_tag( name: "summary", value: "The update for tomcat7 issued as DLA-823-1 caused that the server could
return HTTP 400 errors under certain circumstances. Updated packages are
now available to correct this issue. For reference, the original
advisory text follows.

It was discovered that a programming error in the processing of HTTPS
requests in the Apache Tomcat servlet and JSP engine may result in
denial of service via an infinite loop." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.0-java", ver: "7.0.28-4+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.0-java-doc", ver: "7.0.28-4+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.28-4+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.28-4+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-admin", ver: "7.0.28-4+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-common", ver: "7.0.28-4+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-docs", ver: "7.0.28-4+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-examples", ver: "7.0.28-4+deb7u11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-user", ver: "7.0.28-4+deb7u11", rls: "DEB7" ) )){
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

