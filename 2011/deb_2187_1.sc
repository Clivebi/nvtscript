if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69324" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0059", "CVE-2010-0056" );
	script_name( "Debian Security Advisory DSA 2187-1 (icedove)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202187-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in Icedove, an unbranded
version of the Thunderbird mail/news client.

CVE-2010-1585

Roberto Suggi Liverani discovered that the sanitising performed by
ParanoidFragmentSink was incomplete.

CVE-2011-0053

Crashes in the layout engine may lead to the execution of arbitrary
code.

CVE-2011-0051

Zach Hoffmann discovered that incorrect parsing of recursive eval()
calls could lead to attackers forcing acceptance of a confirmation
dialogue.

CVE-2011-0054, CVE-2010-0056

Christian Holler discovered buffer overflows in the Javascript engine,
which could allow the execution of arbitrary code.

CVE-2011-0055

regenrecht and Igor Bukanov discovered a use-after-free error in the
JSON-Implementation, which could lead to the execution of arbitrary code.

CVE-2011-0057

Daniel Kozlowski discovered that incorrect memory handling the web workers
implementation could lead to the execution of arbitrary code.

CVE-2011-0059

Peleus Uhley discovered a cross-site request forgery risk in the plugin
code.


As indicated in the Lenny (oldstable) release notes, security support for
the Icedove packages in the oldstable needed to be stopped before the end
of the regular Lenny security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a different
mail client.

For the stable distribution (squeeze), this problem has been fixed in
version 3.0.11-1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 3.0.11-2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your icedove packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to icedove
announced via advisory DSA 2187-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icedove", ver: "3.0.11-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dbg", ver: "3.0.11-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dev", ver: "3.0.11-1+squeeze1", rls: "DEB6" ) ) != NULL){
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

