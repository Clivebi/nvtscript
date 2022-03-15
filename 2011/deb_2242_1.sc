if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69740" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-1926" );
	script_name( "Debian Security Advisory DSA 2242-1 (cyrus-imapd-2.2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202242-1" );
	script_tag( name: "insight", value: "It was discovered that the STARTTLS implementation of the Cyrus IMAP
server does not properly restrict I/O buffering, which allows
man-in-the-middle attackers to insert commands into encrypted IMAP,
LMTP, NNTP and POP3 sessions by sending a cleartext command that is
processed after TLS is in place.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.2.13-14+lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 2.2.13-19+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 2.2.13p1-11 for cyrus-imapd-2.2 and in version 2.4.7-1
for cyrus-imapd-2.4." );
	script_tag( name: "solution", value: "We recommend that you upgrade your cyrus-imapd-2.2 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to cyrus-imapd-2.2
announced via advisory DSA 2242-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "2", ver: "2.2.13-14+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcyrus-imap-perl22", ver: "2.2.13-14+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "2", ver: "2.2.13-19+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcyrus-imap-perl22", ver: "2.2.13-19+squeeze1", rls: "DEB6" ) ) != NULL){
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

