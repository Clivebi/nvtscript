if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71262" );
	script_cve_id( "CVE-2012-1183", "CVE-2012-2414", "CVE-2012-2415" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:58:08 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Debian Security Advisory DSA 2460-1 (asterisk)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202460-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the Asterisk PBX and telephony
toolkit:

CVE-2012-1183

Russell Bryant discovered a buffer overflow in the Milliwatt
application.

CVE-2012-2414

David Woolley discovered a privilege escalation in the Asterisk
manager interface.

CVE-2012-2415

Russell Bryant discovered a buffer overflow in the Skinny driver.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.6.2.9-2+squeeze5.

For the unstable distribution (sid), this problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your asterisk packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to asterisk
announced via advisory DSA 2460-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "asterisk", ver: "1:1.6.2.9-2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-config", ver: "1:1.6.2.9-2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1:1.6.2.9-2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1:1.6.2.9-2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1:1.6.2.9-2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-h323", ver: "1:1.6.2.9-2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-sounds-main", ver: "1:1.6.2.9-2+squeeze5", rls: "DEB6" ) ) != NULL){
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

