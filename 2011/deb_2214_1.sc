if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69558" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2011-1401" );
	script_name( "Debian Security Advisory DSA 2214-1 (ikiwiki)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202214-1" );
	script_tag( name: "insight", value: "Tango discovered that ikiwiki, a wiki compiler, is not validating
if the htmlscrubber plugin is enabled or not on a page when adding
alternative stylesheets to pages.  This enables an attacker who is able
to upload custom stylesheets to add malicious stylesheets as an alternate
stylesheet, or replace the default stylesheet, and thus conduct
cross-site scripting attacks.


The oldstable distribution (lenny), this problem has been fixed in
version 2.53.6.

For the stable distribution (squeeze), this problem has been fixed in
version 3.20100815.7.

For the testing distribution (wheezy), this problem has been fixed in
version 3.20110328.

For the testing distribution (sid), this problem has been fixed in
version 3.20110328." );
	script_tag( name: "solution", value: "We recommend that you upgrade your ikiwiki packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to ikiwiki
announced via advisory DSA 2214-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ikiwiki", ver: "2.53.6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ikiwiki", ver: "3.20100815.7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ikiwiki", ver: "3.20110328", rls: "DEB7" ) ) != NULL){
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

