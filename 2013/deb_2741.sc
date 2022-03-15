if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702741" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-2901", "CVE-2013-2887", "CVE-2013-2902", "CVE-2013-2904", "CVE-2013-2900", "CVE-2013-2905", "CVE-2013-2903" );
	script_name( "Debian Security Advisory DSA 2741-1 (chromium-browser - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-08-25 00:00:00 +0200 (Sun, 25 Aug 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2741.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 29.0.1547.57-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 29.0.1547.57-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the Chromium web browser.

CVE-2013-2887
The chrome 29 development team found various issues from internal
fuzzing, audits, and other studies.

CVE-2013-2900
Krystian Bigaj discovered a file handling path sanitization issue.

CVE-2013-2901
Alex Chapman discovered an integer overflow issue in ANGLE, the
Almost Native Graphics Layer.

CVE-2013-2902
cloudfuzzer discovered a use-after-free issue in XSLT.

CVE-2013-2903
cloudfuzzer discovered a use-after-free issue in HTMLMediaElement.

CVE-2013-2904
cloudfuzzer discovered a use-after-free issue in XML document
parsing.

CVE-2013-2905
Christian Jaeger discovered an information leak due to insufficient
file permissions." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromium", ver: "29.0.1547.57-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser", ver: "29.0.1547.57-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-dbg", ver: "29.0.1547.57-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-inspector", ver: "29.0.1547.57-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-l10n", ver: "29.0.1547.57-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "29.0.1547.57-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "29.0.1547.57-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "29.0.1547.57-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

