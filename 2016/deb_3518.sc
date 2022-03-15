if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703518" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_cve_id( "CVE-2016-3153", "CVE-2016-3154" );
	script_name( "Debian Security Advisory DSA 3518-1 (spip - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-16 00:00:00 +0100 (Wed, 16 Mar 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-04-14 21:49:00 +0000 (Thu, 14 Apr 2016)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3518.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|7|9)" );
	script_tag( name: "affected", value: "spip on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), these problems have been fixed
in version 2.1.17-1+deb7u5.

For the stable distribution (jessie), these problems have been fixed in
version 3.0.17-2+deb8u2.

For the testing (stretch) and unstable (sid) distributions, these
problems have been fixed in version 3.0.22-1.

We recommend that you upgrade your spip packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were found in SPIP, a website engine for
publishing, resulting in code injection.

CVE-2016-3153
g0uZ et sambecks, from team root-me, discovered that arbitrary PHP
code could be injected when adding content.

CVE-2016-3154
Gilles Vincent discovered that deserializing untrusted content
could result in arbitrary objects injection." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "spip", ver: "3.0.17-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spip", ver: "2.1.17-1+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spip", ver: "3.0.22-1", rls: "DEB9" ) ) != NULL){
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

