if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703507" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2015-8126", "CVE-2016-1630", "CVE-2016-1631", "CVE-2016-1632", "CVE-2016-1633", "CVE-2016-1634", "CVE-2016-1635", "CVE-2016-1636", "CVE-2016-1637", "CVE-2016-1638", "CVE-2016-1639", "CVE-2016-1640", "CVE-2016-1641", "CVE-2016-1642" );
	script_name( "Debian Security Advisory DSA 3507-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-05 00:00:00 +0100 (Sat, 05 Mar 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3507.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 49.0.2623.75-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 49.0.2623.75-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
discovered in the chromium web browser.

CVE-2015-8126
Joerg Bornemann discovered multiple buffer overflow issues in the
libpng library.

CVE-2016-1630
Mariusz Mlynski discovered a way to bypass the Same Origin Policy
in Blink/Webkit.

CVE-2016-1631
Mariusz Mlynski discovered a way to bypass the Same Origin Policy
in the Pepper Plugin API.

CVE-2016-1632
A bad cast was discovered.

CVE-2016-1633
cloudfuzzer discovered a use-after-free issue in Blink/Webkit.

CVE-2016-1634
cloudfuzzer discovered a use-after-free issue in Blink/Webkit.

CVE-2016-1635
Rob Wu discovered a use-after-free issue in Blink/Webkit.

CVE-2016-1636
A way to bypass SubResource Integrity validation was discovered.

CVE-2016-1637
Keve Nagy discovered an information leak in the skia library.

CVE-2016-1638
Rob Wu discovered a WebAPI bypass issue.

CVE-2016-1639
Khalil Zhani discovered a use-after-free issue in the WebRTC
implementation.

CVE-2016-1640
Luan Herrera discovered an issue with the Extensions user interface.

CVE-2016-1641
Atte Kettunen discovered a use-after-free issue in the handling of
favorite icons.

CVE-2016-1642
The chrome 49 development team found and fixed various issues
during internal auditing. Also multiple issues were fixed in
the v8 javascript library, version 4.9.385.26." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "49.0.2623.75-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "49.0.2623.75-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "49.0.2623.75-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "49.0.2623.75-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "49.0.2623.75-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

