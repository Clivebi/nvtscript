if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70230" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-0084", "CVE-2011-2378", "CVE-2011-2981", "CVE-2011-2982", "CVE-2011-2983", "CVE-2011-2984" );
	script_name( "Debian Security Advisory DSA 2295-1 (iceape)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202295-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been found in the Iceape internet suite, an
unbranded version of Seamonkey:

CVE-2011-0084

regenrecht discovered that incorrect pointer handling in the SVG
processing code could lead to the execution of arbitrary code.

CVE-2011-2378

regenrecht discovered that incorrect memory management in DOM
processing could lead to the execution of arbitrary code.

CVE-2011-2981

moz_bug_r_a_4 discovered a Chrome privilege escalation
vulnerability in the event handler code.

CVE-2011-2982

Gary Kwong, Igor Bukanov, Nils and Bob Clary discovered memory
corruption bugs, which may lead to the execution of arbitrary code.

CVE-2011-2983

shutdown discovered an information leak in the handling of
RegExp.input.

CVE-2011-2984

moz_bug_r_a4 discovered a Chrome privilege escalation
vulnerability.

The oldstable distribution (lenny) is not affected. The iceape
package only  provides the XPCOM code.

For the stable distribution (squeeze), this problem has been fixed in
version 2.0.11-7.

For the unstable distribution (sid), this problem has been fixed in
version 2.0.14-5." );
	script_tag( name: "solution", value: "We recommend that you upgrade your iceape packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to iceape
announced via advisory DSA 2295-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "iceape", ver: "2.0.11-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-browser", ver: "2.0.11-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-chatzilla", ver: "2.0.11-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dbg", ver: "2.0.11-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dev", ver: "2.0.11-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-mailnews", ver: "2.0.11-7", rls: "DEB6" ) ) != NULL){
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

