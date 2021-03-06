if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703351" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2015-1291", "CVE-2015-1292", "CVE-2015-1293", "CVE-2015-1294", "CVE-2015-1295", "CVE-2015-1296", "CVE-2015-1297", "CVE-2015-1298", "CVE-2015-1299", "CVE-2015-1300", "CVE-2015-1301" );
	script_name( "Debian Security Advisory DSA 3351-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-09-03 00:00:00 +0200 (Thu, 03 Sep 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3351.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 45.0.2454.85-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed
once the gcc-5 transition completes.

For the unstable distribution (sid), these problems have been fixed in
version 45.0.2454.85-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2015-1291
A cross-origin bypass issue was discovered in DOM.

CVE-2015-1292
Mariusz Mlynski discovered a cross-origin bypass issue in ServiceWorker.

CVE-2015-1293
Mariusz Mlynski discovered a cross-origin bypass issue in DOM.

CVE-2015-1294
cloudfuzzer discovered a use-after-free issue in the Skia graphics
library.

CVE-2015-1295
A use-after-free issue was discovered in the printing component.

CVE-2015-1296
zcorpan discovered a character spoofing issue.

CVE-2015-1297
Alexander Kashev discovered a permission scoping error.

CVE-2015-1298
Rob Wu discovered an error validating the URL of extensions.

CVE-2015-1299
taro.suzuki.dev discovered a use-after-free issue in the Blink/WebKit
library.

CVE-2015-1300
cgvwzq discovered an information disclosure issue in the Blink/WebKit
library.

CVE-2015-1301
The chrome 45 development team found and fixed various issues
during internal auditing. Also multiple issues were fixed in
the libv8 library, version 4.5.103.29." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "45.0.2454.85-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "45.0.2454.85-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "45.0.2454.85-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "45.0.2454.85-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "45.0.2454.85-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

