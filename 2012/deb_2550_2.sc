if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72441" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-2186", "CVE-2012-3812", "CVE-2012-3863", "CVE-2012-4737" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-03 11:09:39 -0400 (Wed, 03 Oct 2012)" );
	script_name( "Debian Security Advisory DSA 2550-2 (asterisk)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202550-2" );
	script_tag( name: "insight", value: "A regression in the SIP handling code was found in DSA-2550-1.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.6.2.9-2+squeeze8." );
	script_tag( name: "solution", value: "We recommend that you upgrade your asterisk packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to asterisk
announced via advisory DSA 2550-2." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "asterisk", ver: "1:1.6.2.9-2+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-config", ver: "1:1.6.2.9-2+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dbg", ver: "1:1.6.2.9-2+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-dev", ver: "1:1.6.2.9-2+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-doc", ver: "1:1.6.2.9-2+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-h323", ver: "1:1.6.2.9-2+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "asterisk-sounds-main", ver: "1:1.6.2.9-2+squeeze8", rls: "DEB6" ) ) != NULL){
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

