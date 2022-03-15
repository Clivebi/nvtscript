if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70057" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-07 17:37:07 +0200 (Sun, 07 Aug 2011)" );
	script_cve_id( "CVE-2011-1526" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_name( "Debian Security Advisory DSA 2283-1 (krb5-appl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202283-1" );
	script_tag( name: "insight", value: "Tim Zingelmann discovered that due an incorrect configure script the
kerborised FTP server failed to set the effective GID correctly,
resulting in privilege escalation.

The oldstable distribution (lenny) is not affected.

For the stable distribution (squeeze), this problem has been fixed in
version 1.0.1-1.1.

For the unstable distribution (sid), this problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your krb5-appl packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to krb5-appl
announced via advisory DSA 2283-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "krb5-clients", ver: "1:1.0.1-1.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "krb5-ftpd", ver: "1:1.0.1-1.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "krb5-rsh-server", ver: "1:1.0.1-1.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "krb5-telnetd", ver: "1:1.0.1-1.1", rls: "DEB6" ) ) != NULL){
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

