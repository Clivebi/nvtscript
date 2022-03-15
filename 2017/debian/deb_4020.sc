if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704020" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-15386", "CVE-2017-15387", "CVE-2017-15388", "CVE-2017-15389", "CVE-2017-15390", "CVE-2017-15391", "CVE-2017-15392", "CVE-2017-15393", "CVE-2017-15394", "CVE-2017-15395", "CVE-2017-15396", "CVE-2017-5124", "CVE-2017-5125", "CVE-2017-5126", "CVE-2017-5127", "CVE-2017-5128", "CVE-2017-5129", "CVE-2017-5131", "CVE-2017-5132", "CVE-2017-5133" );
	script_name( "Debian Security Advisory DSA 4020-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-05 00:00:00 +0100 (Sun, 05 Nov 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4020.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), security support for chromium has
been discontinued.

For the stable distribution (stretch), these problems have been fixed in
version 62.0.3202.75-1~deb9u1.

For the testing distribution (buster), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 62.0.3202.75-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the chromium web browser.

In addition, this message serves as an annoucment that security support for
chromium in the oldstable release (jessie), Debian 8, is now discontinued.

Debian 8 chromium users that desire continued security updates are strongly
encouraged to upgrade now to the current stable release (stretch), Debian 9.

An alternative is to switch to the firefox browser, which will continue to
receive security updates in jessie for some time.

CVE-2017-5124
A cross-site scripting issue was discovered in MHTML.

CVE-2017-5125
A heap overflow issue was discovered in the skia library.

CVE-2017-5126
Luat Nguyen discovered a use-after-free issue in the pdfium library.

CVE-2017-5127
Luat Nguyen discovered another use-after-free issue in the pdfium
library.

CVE-2017-5128
Omair discovered a heap overflow issue in the WebGL implementation.

CVE-2017-5129
Omair discovered a use-after-free issue in the WebAudio implementation.

CVE-2017-5131
An out-of-bounds write issue was discovered in the skia library.

CVE-2017-5132
Guarav Dewan discovered an error in the WebAssembly implementation.

CVE-2017-5133
Aleksandar Nikolic discovered an out-of-bounds write issue in the skia
library.

CVE-2017-15386
WenXu Wu discovered a user interface spoofing issue.

CVE-2017-15387
Jun Kokatsu discovered a way to bypass the content security policy.

CVE-2017-15388
Kushal Arvind Shah discovered an out-of-bounds read issue in the skia
library.

CVE-2017-15389
xisigr discovered a URL spoofing issue.

CVE-2017-15390
Haosheng Wang discovered a URL spoofing issue.

CVE-2017-15391
Joao Lucas Melo Brasio discovered a way for an extension to bypass its
limitations.

CVE-2017-15392
Xiaoyin Liu discovered an error the implementation of registry keys.

CVE-2017-15393
Svyat Mitin discovered an issue in the devtools.

CVE-2017-15394
Sam discovered a URL spoofing issue.

CVE-2017-15395
Johannes Bergman discovered a null pointer dereference issue.

CVE-2017-15396
Yuan Deng discovered a stack overflow issue in the v8 javascript library." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "62.0.3202.75-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "62.0.3202.75-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-driver", ver: "62.0.3202.75-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "62.0.3202.75-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-shell", ver: "62.0.3202.75-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-widevine", ver: "62.0.3202.75-1~deb9u1", rls: "DEB9" ) ) != NULL){
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

