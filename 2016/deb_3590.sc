if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703590" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2016-1667", "CVE-2016-1668", "CVE-2016-1669", "CVE-2016-1670", "CVE-2016-1672", "CVE-2016-1673", "CVE-2016-1674", "CVE-2016-1675", "CVE-2016-1676", "CVE-2016-1677", "CVE-2016-1678", "CVE-2016-1679", "CVE-2016-1680", "CVE-2016-1681", "CVE-2016-1682", "CVE-2016-1683", "CVE-2016-1684", "CVE-2016-1685", "CVE-2016-1686", "CVE-2016-1687", "CVE-2016-1688", "CVE-2016-1689", "CVE-2016-1690", "CVE-2016-1691", "CVE-2016-1692", "CVE-2016-1693", "CVE-2016-1694", "CVE-2016-1695" );
	script_name( "Debian Security Advisory DSA 3590-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-01 00:00:00 +0200 (Wed, 01 Jun 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3590.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these
problems have been fixed in version 51.0.2704.63-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 51.0.2704.63-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
discovered in the chromium web browser.

CVE-2016-1667
Mariusz Mylinski discovered a cross-origin bypass.

CVE-2016-1668
Mariusz Mylinski discovered a cross-origin bypass in bindings to v8.

CVE-2016-1669
Choongwoo Han discovered a buffer overflow in the v8 javascript
library.

CVE-2016-1670
A race condition was found that could cause the renderer process
to reuse ids that should have been unique.

CVE-2016-1672
Mariusz Mylinski discovered a cross-origin bypass in extension
bindings.

CVE-2016-1673
Mariusz Mylinski discovered a cross-origin bypass in Blink/Webkit.

CVE-2016-1674
Mariusz Mylinski discovered another cross-origin bypass in extension
bindings.

CVE-2016-1675
Mariusz Mylinski discovered another cross-origin bypass in
Blink/Webkit.

CVE-2016-1676
Rob Wu discovered a cross-origin bypass in extension bindings.

CVE-2016-1677
Guang Gong discovered a type confusion issue in the v8 javascript
library.

CVE-2016-1678
Christian Holler discovered an overflow issue in the v8 javascript
library.

CVE-2016-1679
Rob Wu discovered a use-after-free issue in the bindings to v8.

CVE-2016-1680
Atte Kettunen discovered a use-after-free issue in the skia library.

CVE-2016-1681
Aleksandar Nikolic discovered an overflow issue in the pdfium
library.

CVE-2016-1682
KingstonTime discovered a way to bypass the Content Security Policy.

CVE-2016-1683
Nicolas Gregoire discovered an out-of-bounds write issue in the
libxslt library.

CVE-2016-1684
Nicolas Gregoire discovered an integer overflow issue in the
libxslt library.

CVE-2016-1685
Ke Liu discovered an out-of-bounds read issue in the pdfium library.

CVE-2016-1686
Ke Liu discovered another out-of-bounds read issue in the pdfium
library.

CVE-2016-1687
Rob Wu discovered an information leak in the handling of extensions.

CVE-2016-1688
Max Korenko discovered an out-of-bounds read issue in the v8
javascript library.

CVE-2016-1689
Rob Wu discovered a buffer overflow issue.

CVE-2016-1690
Rob Wu discovered a use-after-free issue.

CVE-2016-1691
Atte Kettunen discovered a buffer overflow issue in the skia library.

CVE-2016-1692
Til Jasper Ullrich discovered a cross-origin bypass issue.

CVE-2016-1693
Khalil Zhani discovered that the Software Removal Tool download was
done over an HTTP connection.

CVE-2016-1694
Ryan Lester and Bryant Zadegan discovered that pinned public keys
would be removed when clearing the browser cache.

CVE-2016-1695
The chrome development team found and fixed various issues during
internal auditing." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "51.0.2704.63-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "51.0.2704.63-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "51.0.2704.63-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "51.0.2704.63-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "51.0.2704.63-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

