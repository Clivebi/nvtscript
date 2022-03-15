if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70227" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-4554", "CVE-2010-4555", "CVE-2011-2023", "CVE-2011-2752", "CVE-2011-2753" );
	script_name( "Debian Security Advisory DSA 2291-1 (squirrelmail)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202291-1" );
	script_tag( name: "insight", value: "Various vulnerabilities have been found in SquirrelMail, a webmail
application. The Common Vulnerabilities and Exposures project
identifies the following vulnerabilities:

CVE-2010-4554

SquirrelMail did not prevent page rendering inside a third-party
HTML frame, which makes it easier for remote attackers to conduct
clickjacking attacks via a crafted web site.

CVE-2010-4555, CVE-2011-2752, CVE-2011-2753

Multiple small bugs in SquirrelMail allowed an attacker to inject
malicious script into various pages or alter the contents of user
preferences.

CVE-2011-2023

It was possible to inject arbitrary web script or HTML via a
crafted STYLE element in an HTML part of an e-mail message.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.15-4+lenny5.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.21-2.

For the testing (wheezy) and unstable distribution (sid), these problems
have been fixed in version 1.4.22-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your squirrelmail packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to squirrelmail
announced via advisory DSA 2291-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "squirrelmail", ver: "2:1.4.15-4+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "squirrelmail", ver: "2:1.4.21-2", rls: "DEB6" ) ) != NULL){
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

