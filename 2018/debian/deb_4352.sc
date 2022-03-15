if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704352" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2018-17480", "CVE-2018-17481", "CVE-2018-18335", "CVE-2018-18336", "CVE-2018-18337", "CVE-2018-18338", "CVE-2018-18339", "CVE-2018-18340", "CVE-2018-18341", "CVE-2018-18342", "CVE-2018-18343", "CVE-2018-18344", "CVE-2018-18345", "CVE-2018-18346", "CVE-2018-18347", "CVE-2018-18348", "CVE-2018-18349", "CVE-2018-18350", "CVE-2018-18351", "CVE-2018-18352", "CVE-2018-18353", "CVE-2018-18354", "CVE-2018-18355", "CVE-2018-18356", "CVE-2018-18357", "CVE-2018-18358", "CVE-2018-18359" );
	script_name( "Debian Security Advisory DSA 4352-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-12-07 00:00:00 +0100 (Fri, 07 Dec 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-17 21:15:00 +0000 (Sat, 17 Aug 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4352.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 71.0.3578.80-1~deb9u1.

We recommend that you upgrade your chromium-browser packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/chromium-browser" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-17480
Guang Gong discovered an out-of-bounds write issue in the v8 javascript
library.

CVE-2018-17481
Several use-after-free issues were discovered in the pdfium library.

CVE-2018-18335
A buffer overflow issue was discovered in the skia library.

CVE-2018-18336
Huyna discovered a use-after-free issue in the pdfium library.

CVE-2018-18337
cloudfuzzer discovered a use-after-free issue in blink/webkit.

CVE-2018-18338
Zhe Jin discovered a buffer overflow issue in the canvas renderer.

CVE-2018-18339
cloudfuzzer discovered a use-after-free issue in the WebAudio
implementation.

CVE-2018-18340
A use-after-free issue was discovered in the MediaRecorder implementation.

CVE-2018-18341
cloudfuzzer discovered a buffer overflow issue in blink/webkit.

CVE-2018-18342
Guang Gong discovered an out-of-bounds write issue in the v8 javascript
library.

CVE-2018-18343
Tran Tien Hung discovered a use-after-free issue in the skia library.

CVE-2018-18344
Jann Horn discovered an error in the Extensions implementation.

CVE-2018-18345
Masato Kinugawa and Jun Kokatsu discovered an error in the Site Isolation
feature.

CVE-2018-18346
Luan Herrera discovered an error in the user interface.

CVE-2018-18347
Luan Herrera discovered an error in the Navigation implementation.

CVE-2018-18348
Ahmed Elsobky discovered an error in the omnibox implementation.

CVE-2018-18349
David Erceg discovered a policy enforcement error.

CVE-2018-18350
Jun Kokatsu discovered a policy enforcement error.

CVE-2018-18351
Jun Kokatsu discovered a policy enforcement error.

CVE-2018-18352
Jun Kokatsu discovered an error in Media handling.

CVE-2018-18353
Wenxu Wu discovered an error in the network authentication implementation.

CVE-2018-18354
Wenxu Wu discovered an error related to integration with GNOME Shell.

CVE-2018-18355
evil1m0 discovered a policy enforcement error.

CVE-2018-18356
Tran Tien Hung discovered a use-after-free issue in the skia library.

CVE-2018-18357
evil1m0 discovered a policy enforcement error.

CVE-2018-18358
Jann Horn discovered a policy enforcement error.

CVE-2018-18359
cyrilliu discovered an out-of-bounds read issue in the v8 javascript
library.

Several additional security relevant issues are also fixed in this update
that have not yet received CVE identifiers." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "chromedriver", ver: "71.0.3578.80-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium", ver: "71.0.3578.80-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-driver", ver: "71.0.3578.80-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-l10n", ver: "71.0.3578.80-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-shell", ver: "71.0.3578.80-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-widevine", ver: "71.0.3578.80-1~deb9u1", rls: "DEB9" ) )){
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

