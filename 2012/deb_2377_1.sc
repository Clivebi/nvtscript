if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70696" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-3481" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:25:02 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2377-1 (cyrus-imapd-2.2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202377-1" );
	script_tag( name: "insight", value: "It was discovered that cyrus-imapd, a highly scalable mail system designed
for use in enterprise environments, is not properly parsing mail headers
when a client makes use of the IMAP threading feature.  As a result, a NULL
pointer is dereferenced which crashes the daemon.  An attacker can trigger
this by sending a mail containing crafted reference headers and access the
mail with a client that uses the server threading feature of IMAP.


For the oldstable distribution (lenny), this problem has been fixed in
version 2.2.13-14+lenny6.

For the stable distribution (squeeze), this problem has been fixed in
version 2.2.13-19+squeeze3.

For the testing (wheezy) and unstable (sid) distributions, this problem has been
fixed in cyrus-imapd-2.4 version 2.4.11-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your cyrus-imapd-2.2 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to cyrus-imapd-2.2
announced via advisory DSA 2377-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cyrus-admin-2.2", ver: "2.2.13-14+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-clients-2.2", ver: "2.2.13-14+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-common-2.2", ver: "2.2.13-14+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-dev-2.2", ver: "2.2.13-14+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-doc-2.2", ver: "2.2.13-14+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-imapd-2.2", ver: "2.2.13-14+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-murder-2.2", ver: "2.2.13-14+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-nntpd-2.2", ver: "2.2.13-14+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-pop3d-2.2", ver: "2.2.13-14+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcyrus-imap-perl22", ver: "2.2.13-14+lenny6", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-admin-2.2", ver: "2.2.13-19+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-clients-2.2", ver: "2.2.13-19+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-common-2.2", ver: "2.2.13-19+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-dev-2.2", ver: "2.2.13-19+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-doc-2.2", ver: "2.2.13-19+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-imapd-2.2", ver: "2.2.13-19+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-murder-2.2", ver: "2.2.13-19+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-nntpd-2.2", ver: "2.2.13-19+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-pop3d-2.2", ver: "2.2.13-19+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcyrus-imap-perl22", ver: "2.2.13-19+squeeze3", rls: "DEB6" ) ) != NULL){
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

