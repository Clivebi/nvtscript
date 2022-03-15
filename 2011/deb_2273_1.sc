if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69980" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_cve_id( "CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2365", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2376" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Debian Security Advisory DSA 2273-1 (icedove)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202273-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in Icedove, an unbranded
version of the Thunderbird mail/news client.

CVE-2011-0083 / CVE-2011-2363

regenrecht discovered two use-after-frees in SVG processing,
which could lead to the execution of arbitrary code.

CVE-2011-0085

regenrecht discovered a use-after-free in XUL processing, which
could lead to the execution of arbitrary code.

CVE-2011-2362

David Chan discovered that cookies were insufficiently isolated.

CVE-2011-2371

Chris Rohlf and Yan Ivnitskiy discovered an integer overflow in the
Javascript engine, which could lead to the execution of arbitrary
code.

CVE-2011-2373

Martin Barbella discovered a use-after-free in XUL processing,
which could lead to the execution of arbitrary code.

CVE-2011-2374

Bob Clary, Kevin Brosnan, Nils, Gary Kwong, Jesse Ruderman and
Christian Biesinger discovered memory corruption bugs, which may
lead to the execution of arbitrary code.

CVE-2011-2376

Luke Wagner and Gary Kwong discovered memory corruption bugs, which
may lead to the execution of arbitrary code.

As indicated in the Lenny (oldstable) release notes, security support for
the Icedove packages in the oldstable needed to be stopped before the end
of the regular Lenny security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a different
mail client.

For the stable distribution (squeeze), this problem has been fixed in
version 3.0.11-1+squeeze3.

For the unstable distribution (sid), this problem has been fixed in
version 3.1.11-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your icedove packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to icedove
announced via advisory DSA 2273-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icedove", ver: "3.0.11-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dbg", ver: "3.0.11-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dev", ver: "3.0.11-1+squeeze3", rls: "DEB6" ) ) != NULL){
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

