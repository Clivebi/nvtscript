if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69983" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_cve_id( "CVE-2011-2516" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Debian Security Advisory DSA 2277-1 (xml-security-c)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202277-1" );
	script_tag( name: "insight", value: "It has been discovered that xml-security-c, an implementation of the XML
Digital Signature and Encryption specifications, is not properly handling
RSA keys of sizes on the order of 8192 or more bits.  This allows an
attacker to crash applications using this functionality or potentially
execute arbitrary code by tricking an application into verifying a signature
created with a sufficiently long RSA key.


For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.0-3+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.5.1-3+squeeze1.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1.6.1-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your xml-security-c packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to xml-security-c
announced via advisory DSA 2277-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxml-security-c-dev", ver: "1.4.0-3+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-security-c14", ver: "1.4.0-3+lenny3", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-security-c-dev", ver: "1.5.1-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-security-c15", ver: "1.5.1-3+squeeze1", rls: "DEB6" ) ) != NULL){
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

