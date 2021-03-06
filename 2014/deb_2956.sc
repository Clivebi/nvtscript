if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702956" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-7106", "CVE-2013-7107", "CVE-2013-7108", "CVE-2014-1878", "CVE-2014-2386" );
	script_name( "Debian Security Advisory DSA 2956-1 (icinga - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-11 00:00:00 +0200 (Wed, 11 Jun 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2956.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "icinga on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 1.7.1-7.

For the testing distribution (jessie), these problems have been fixed in
version 1.11.0-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.11.0-1.

We recommend that you upgrade your icinga packages." );
	script_tag( name: "summary", value: "Multiple security issues have been found in the Icinga host and network
monitoring system (buffer overflows, cross-site request forgery, off-by
ones) which could result in the execution of arbitrary code, denial of
service or session hijacking." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icinga", ver: "1.7.1-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icinga-cgi", ver: "1.7.1-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icinga-common", ver: "1.7.1-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icinga-core", ver: "1.7.1-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icinga-dbg", ver: "1.7.1-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icinga-doc", ver: "1.7.1-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icinga-idoutils", ver: "1.7.1-7", rls: "DEB7" ) ) != NULL){
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

