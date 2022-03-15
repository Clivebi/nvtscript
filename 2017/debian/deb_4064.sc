if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704064" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-15407", "CVE-2017-15408", "CVE-2017-15409", "CVE-2017-15410", "CVE-2017-15411", "CVE-2017-15413", "CVE-2017-15415", "CVE-2017-15416", "CVE-2017-15417", "CVE-2017-15418", "CVE-2017-15419", "CVE-2017-15420", "CVE-2017-15423", "CVE-2017-15424", "CVE-2017-15425", "CVE-2017-15426", "CVE-2017-15427" );
	script_name( "Debian Security Advisory DSA 4064-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-12 00:00:00 +0100 (Tue, 12 Dec 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-20 18:13:00 +0000 (Tue, 20 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4064.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 63.0.3239.84-1~deb9u1.

We recommend that you upgrade your chromium-browser packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/chromium-browser" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2017-15407
Ned Williamson discovered an out-of-bounds write issue.

CVE-2017-15408
Ke Liu discovered a heap overflow issue in the pdfium library.

CVE-2017-15409
An out-of-bounds write issue was discovered in the skia library.

CVE-2017-15410
Luat Nguyen discovered a use-after-free issue in the pdfium library.

CVE-2017-15411
Luat Nguyen discovered a use-after-free issue in the pdfium library.

CVE-2017-15413
Gaurav Dewan discovered a type confusion issue.

CVE-2017-15415
Viktor Brange discovered an information disclosure issue.

CVE-2017-15416
Ned Williamson discovered an out-of-bounds read issue.

CVE-2017-15417
Max May discovered an information disclosure issue in the skia
library.

CVE-2017-15418
Kushal Arvind Shah discovered an uninitialized value in the skia
library.

CVE-2017-15419
Jun Kokatsu discoved an information disclosure issue.

CVE-2017-15420
WenXu Wu discovered a URL spoofing issue.

CVE-2017-15423
Greg Hudson discovered an issue in the boringssl library.

CVE-2017-15424
Khalil Zhani discovered a URL spoofing issue.

CVE-2017-15425
xisigr discovered a URL spoofing issue.

CVE-2017-15426
WenXu Wu discovered a URL spoofing issue.

CVE-2017-15427
Junaid Farhan discovered an issue with the omnibox." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "chromedriver", ver: "63.0.3239.84-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium", ver: "63.0.3239.84-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-driver", ver: "63.0.3239.84-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-l10n", ver: "63.0.3239.84-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-shell", ver: "63.0.3239.84-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-widevine", ver: "63.0.3239.84-1~deb9u1", rls: "DEB9" ) )){
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

