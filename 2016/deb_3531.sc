if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703531" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2016-1646", "CVE-2016-1647", "CVE-2016-1648", "CVE-2016-1649", "CVE-2016-1650" );
	script_name( "Debian Security Advisory DSA 3531-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-25 00:00:00 +0100 (Fri, 25 Mar 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3531.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 49.0.2623.108-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 49.0.2623.108-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
discovered in the chromium web browser.

CVE-2016-1646
Wen Xu discovered an out-of-bounds read issue in the v8 library.

CVE-2016-1647
A use-after-free issue was discovered.

CVE-2016-1648
A use-after-free issue was discovered in the handling of extensions.

CVE-2016-1649
lokihardt discovered a buffer overflow issue in the Almost Native
Graphics Layer Engine (ANGLE) library.

CVE-2016-1650
The chrome development team found and fixed various issues during
internal auditing. Also multiple issues were fixed in the v8
javascript library, version 4.9.385.33." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "49.0.2623.108-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "49.0.2623.108-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "49.0.2623.108-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "49.0.2623.108-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "49.0.2623.108-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

