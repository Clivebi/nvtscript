if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69974" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-1447" );
	script_name( "Debian Security Advisory DSA 2267-1 (perl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202267-1" );
	script_tag( name: "insight", value: "It was discovered that Perl's Safe module - a module to compile and
execute code in restricted compartments - could by bypassed.

Please note that this update is known to break Petal, an XML-based
templating engine (shipped with Debian 6.0/Squeeze in the package
libpetal-perl). A fix is not yet available. If you use Petal, you might
consider to put the previous Perl packages on hold.

For the oldstable distribution (lenny), this problem has been fixed in
version 5.10.0-19lenny5.

For the stable distribution (squeeze), this problem has been fixed in
version 5.10.1-17squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 5.12.3-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your perl packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to perl
announced via advisory DSA 2267-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libcgi-fast-perl", ver: "5.10.0-19lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libperl-dev", ver: "5.10.0-19lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libperl5.10", ver: "5.10.0-19lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl", ver: "5.10.0-19lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-base", ver: "5.10.0-19lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-debug", ver: "5.10.0-19lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-doc", ver: "5.10.0-19lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-modules", ver: "5.10.0-19lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-suid", ver: "5.10.0-19lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcgi-fast-perl", ver: "5.10.1-17squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libperl-dev", ver: "5.10.1-17squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libperl5.10", ver: "5.10.1-17squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl", ver: "5.10.1-17squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-base", ver: "5.10.1-17squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-debug", ver: "5.10.1-17squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-doc", ver: "5.10.1-17squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-modules", ver: "5.10.1-17squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-suid", ver: "5.10.1-17squeeze2", rls: "DEB6" ) ) != NULL){
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

