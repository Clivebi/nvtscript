if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702811" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-6639", "CVE-2013-6636", "CVE-2013-6638", "CVE-2013-6640", "CVE-2013-6634", "CVE-2013-6637", "CVE-2013-6635" );
	script_name( "Debian Security Advisory DSA 2811-1 (chromium-browser - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-12-07 00:00:00 +0100 (Sat, 07 Dec 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2811.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 31.0.1650.63-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 31.0.1650.63-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2013-6634
Andrey Labunets discovered that the wrong URL was used during
validation in the one-click sign on helper.

CVE-2013-6635
cloudfuzzer discovered use-after-free issues in the InsertHTML and
Indent DOM editing commands.

CVE-2013-6636
Bas Venis discovered an address bar spoofing issue.

CVE-2013-6637
The chrome 31 development team discovered and fixed multiple issues
with potential security impact.

CVE-2013-6638
Jakob Kummerow of the Chromium project discovered a buffer overflow in
the v8 javascript library.

CVE-2013-6639
Jakob Kummerow of the Chromium project discovered an out-of-bounds
write in the v8 javascript library.

CVE-2013-6640
Jakob Kummerow of the Chromium project discovered an out-of-bounds
read in the v8 javascript library." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromium", ver: "31.0.1650.63-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser", ver: "31.0.1650.63-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-dbg", ver: "31.0.1650.63-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-inspector", ver: "31.0.1650.63-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-l10n", ver: "31.0.1650.63-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "31.0.1650.63-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "31.0.1650.63-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "31.0.1650.63-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

