if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703172" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2014-9679" );
	script_name( "Debian Security Advisory DSA 3172-1 (cups - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-25 00:00:00 +0100 (Wed, 25 Feb 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3172.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "cups on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.5.3-5+deb7u5.

For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version 1.7.5-11.

We recommend that you upgrade your cups packages." );
	script_tag( name: "summary", value: "Peter De Wachter discovered that CUPS,
the Common UNIX Printing System, did not correctly parse compressed raster files.
By submitting a specially crafted raster file, a remote attacker could use this
vulnerability to trigger a buffer overflow." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cups", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-bsd", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-client", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-common", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-dbg", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-ppdc", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cupsddk", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcups2", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcups2-dev", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupscgi1", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupscgi1-dev", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsdriver1", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsdriver1-dev", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsimage2", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsimage2-dev", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsmime1", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsmime1-dev", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsppdc1", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsppdc1-dev", ver: "1.5.3-5+deb7u5", rls: "DEB7" ) ) != NULL){
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

