if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71144" );
	script_cve_id( "CVE-2012-1103" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-12 11:31:52 -0400 (Mon, 12 Mar 2012)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "Debian Security Advisory DSA 2416-1 (notmuch)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202416-1" );
	script_tag( name: "insight", value: "It was discovered that Notmuch, an email indexer, did not sufficiently
escape Emacs MML tags. When using the Emacs interface, a user could
be tricked into replying to a maliciously formatted message which could
lead to files from the local machine being attached to the outgoing
message.

For the stable distribution (squeeze), this problem has been fixed in
version 0.3.1+squeeze1.

For the testing distribution (wheezy) and unstable distribution (sid),
this problem has been fixed in version 0.11.1-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your notmuch packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to notmuch
announced via advisory DSA 2416-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnotmuch-dev", ver: "0.3.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnotmuch1", ver: "0.3.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "notmuch", ver: "0.3.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnotmuch-dev", ver: "0.11.1-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnotmuch2", ver: "0.11.1-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "notmuch", ver: "0.11.1-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "notmuch-emacs", ver: "0.11.1-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "notmuch-vim", ver: "0.11.1-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-notmuch", ver: "0.11.1-1", rls: "DEB7" ) ) != NULL){
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

