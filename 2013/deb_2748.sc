if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702748" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1438" );
	script_name( "Debian Security Advisory DSA 2748-1 (exactimage - denial of service)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-01 00:00:00 +0200 (Sun, 01 Sep 2013)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2748.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "exactimage on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 0.8.1-3+deb6u2.

For the stable distribution (wheezy), this problem has been fixed in
version 0.8.5-5+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.9-1.

We recommend that you upgrade your exactimage packages." );
	script_tag( name: "summary", value: "Several denial-of-service vulnerabilities were discovered in the dcraw
code base, a program for processing raw format images from digital
cameras. This update corrects them in the copy that is embedded in
the exactimage package." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "exactimage", ver: "0.8.1-3+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exactimage-dbg", ver: "0.8.1-3+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exactimage-perl", ver: "0.8.1-3+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexactimage-perl", ver: "0.8.1-3+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-exactimage", ver: "0.8.1-3+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-exactimage", ver: "0.8.1-3+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "edisplay", ver: "0.8.5-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exactimage", ver: "0.8.5-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exactimage-dbg", ver: "0.8.5-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexactimage-perl", ver: "0.8.5-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-exactimage", ver: "0.8.5-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-exactimage", ver: "0.8.5-5+deb7u2", rls: "DEB7" ) ) != NULL){
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

