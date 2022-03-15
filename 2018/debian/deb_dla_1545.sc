if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891545" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2018-11784" );
	script_name( "Debian LTS: Security Advisory for tomcat8 (DLA-1545-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-16 00:00:00 +0200 (Tue, 16 Oct 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-11 22:29:00 +0000 (Tue, 11 Jun 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/10/msg00006.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "tomcat8 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
8.0.14-1+deb8u14.

We recommend that you upgrade your tomcat8 packages." );
	script_tag( name: "summary", value: "Sergey Bobrov discovered that when the default servlet returned a
redirect to a directory (e.g. redirecting to /foo/ when the user
requested /foo) a specially crafted URL could be used to cause the
redirect to be generated to any URI of the attackers choice." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.1-java", ver: "8.0.14-1+deb8u14", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.1-java-doc", ver: "8.0.14-1+deb8u14", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.0.14-1+deb8u14", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8", ver: "8.0.14-1+deb8u14", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-admin", ver: "8.0.14-1+deb8u14", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-common", ver: "8.0.14-1+deb8u14", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-docs", ver: "8.0.14-1+deb8u14", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-examples", ver: "8.0.14-1+deb8u14", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-user", ver: "8.0.14-1+deb8u14", rls: "DEB8" ) )){
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

