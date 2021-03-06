if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72567" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-3982", "CVE-2012-3986", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4182", "CVE-2012-4186", "CVE-2012-4188", "CVE-2012-3959" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-16 03:15:37 -0500 (Fri, 16 Nov 2012)" );
	script_name( "Debian Security Advisory DSA 2572-1 (iceape)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202572-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in Iceape, an internet
suite based on Seamonkey:

CVE-2012-3982
Multiple unspecified vulnerabilities in the browser engine
allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute
arbitrary code via unknown vectors.

CVE-2012-3986
Icedove does not properly restrict calls to DOMWindowUtils
methods, which allows remote attackers to bypass intended
access restrictions via crafted JavaScript code.

CVE-2012-3990
A Use-after-free vulnerability in the IME State Manager
implementation allows remote attackers to execute arbitrary
code via unspecified vectors, related to the
nsIContent::GetNameSpaceID function.

CVE-2012-3991
Icedove does not properly restrict JSAPI access to the
GetProperty function, which allows remote attackers to bypass
the Same Origin Policy and possibly have unspecified other
impact via a crafted web site.

CVE-2012-4179
A use-after-free vulnerability in the
nsHTMLCSSUtils::CreateCSSPropertyTxn function allows remote
attackers to execute arbitrary code or cause a denial of
service (heap memory corruption) via unspecified vectors.

CVE-2012-4180
A heap-based buffer overflow in the
nsHTMLEditor::IsPrevCharInNodeWhitespace function allows
remote attackers to execute arbitrary code via unspecified
vectors.

CVE-2012-4182
A use-after-free vulnerability in the
nsTextEditRules::WillInsert function allows remote attackers
to execute arbitrary code or cause a denial of service (heap
memory corruption) via unspecified vectors.

CVE-2012-4186
A heap-based buffer overflow in the
nsWav-eReader::DecodeAudioData function allows remote attackers
to execute arbitrary code via unspecified vectors.

CVE-2012-4188
A heap-based buffer overflow in the Convolve3x3 function
allows remote attackers to execute arbitrary code via
unspecified vectors.

Additionally, this update fixes a regression in the patch for
CVE-2012-3959, released in DSA-2554-1.

For the stable distribution (squeeze), these problems have been fixed in
version 2.0.11-16.

For the testing distribution (wheezy), these problems have been fixed in
version 10.0.10esr-1.

For the unstable distribution (sid), these problems have been fixed in
version 10.0.10esr-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your iceape packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to iceape
announced via advisory DSA 2572-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "iceape", ver: "2.0.11-16", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-browser", ver: "2.0.11-16", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-chatzilla", ver: "2.0.11-16", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dbg", ver: "2.0.11-16", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dev", ver: "2.0.11-16", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-mailnews", ver: "2.0.11-16", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-browser", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-chatzilla", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dbg", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-all", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-be", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-ca", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-cs", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-de", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-en-gb", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-es-ar", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-es-es", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-fi", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-fr", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-gl", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-hu", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-it", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-ja", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-lt", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-nb-no", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-nl", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-pl", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-pt-pt", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-ru", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-sk", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-sv-se", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-tr", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-l10n-zh-cn", ver: "2.7.10-1", rls: "DEB7" ) ) != NULL){
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

