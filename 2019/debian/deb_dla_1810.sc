if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891810" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-0221" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-13 17:15:00 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-06-01 09:22:33 +0000 (Sat, 01 Jun 2019)" );
	script_name( "Debian LTS: Security Advisory for tomcat7 (DLA-1810-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00044.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1810-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat7'
  package(s) announced via the DLA-1810-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Nightwatch Cybersecurity Research team identified an XSS vulnerability
in tomcat7. The SSI printenv command echoes user provided data without
escaping. SSI is disabled by default. The printenv command is intended
for debugging and is unlikely to be present in a production website." );
	script_tag( name: "affected", value: "'tomcat7' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
7.0.56-3+really7.0.94-1.

We recommend that you upgrade your tomcat7 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.0-java", ver: "7.0.56-3+really7.0.94-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.0-java-doc", ver: "7.0.56-3+really7.0.94-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat7-java", ver: "7.0.56-3+really7.0.94-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7", ver: "7.0.56-3+really7.0.94-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-admin", ver: "7.0.56-3+really7.0.94-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-common", ver: "7.0.56-3+really7.0.94-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-docs", ver: "7.0.56-3+really7.0.94-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-examples", ver: "7.0.56-3+really7.0.94-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat7-user", ver: "7.0.56-3+really7.0.94-1", rls: "DEB8" ) )){
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

