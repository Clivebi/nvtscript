if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69107" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Debian Security Advisory DSA 2173-1 (pam-pgsql)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_tag( name: "insight", value: "It was discovered that pam-pgsql, a PAM module to authenticate using
a PostgreSQL database, was vulnerable to a buffer overflow in supplied
IP-addresses." );
	script_tag( name: "summary", value: "The remote host is missing an update to pam-pgsql
announced via advisory DSA 2173-1." );
	script_tag( name: "solution", value: "For the oldstable distribution (lenny), this problem has been fixed in
version 0.6.3-2+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 0.7.1-4+squeeze1.

For the testing (wheezy) and unstable (sid) distributions, this problem
has been fixed in version 0.7.1-5.

We recommend that you upgrade your pam-pgsql packages." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202173-1" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpam-pgsql", ver: "0.6.3-2+lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-pgsql", ver: "0.7.1-4+squeeze1", rls: "DEB6" ) ) != NULL){
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

