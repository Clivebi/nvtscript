if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703926" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_cve_id( "CVE-2017-5087", "CVE-2017-5088", "CVE-2017-5089", "CVE-2017-5091", "CVE-2017-5092", "CVE-2017-5093", "CVE-2017-5094", "CVE-2017-5095", "CVE-2017-5097", "CVE-2017-5098", "CVE-2017-5099", "CVE-2017-5100", "CVE-2017-5101", "CVE-2017-5102", "CVE-2017-5103", "CVE-2017-5104", "CVE-2017-5105", "CVE-2017-5106", "CVE-2017-5107", "CVE-2017-5108", "CVE-2017-5109", "CVE-2017-5110", "CVE-2017-7000" );
	script_name( "Debian Security Advisory DSA 3926-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-04 00:00:00 +0200 (Fri, 04 Aug 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3926.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 60.0.3112.78-1~deb9u1.

For the unstable distribution (sid), these problems have been fixed in
version 60.0.3112.78-1 or earlier versions.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2017-5087
Ned Williamson discovered a way to escape the sandbox.

CVE-2017-5088
Xiling Gong discovered an out-of-bounds read issue in the v8 javascript
library.

CVE-2017-5089
Michal Bentkowski discovered a spoofing issue.

CVE-2017-5091
Ned Williamson discovered a use-after-free issue in IndexedDB.

CVE-2017-5092
Yu Zhou discovered a use-after-free issue in PPAPI.

CVE-2017-5093
Luan Herrera discovered a user interface spoofing issue.

CVE-2017-5094
A type confusion issue was discovered in extensions.

CVE-2017-5095
An out-of-bounds write issue was discovered in the pdfium library.

CVE-2017-5097
An out-of-bounds read issue was discovered in the skia library.

CVE-2017-5098
Jihoon Kim discover a use-after-free issue in the v8 javascript library.

CVE-2017-5099
Yuan Deng discovered an out-of-bounds write issue in PPAPI.

CVE-2017-5100
A use-after-free issue was discovered in Chrome Apps.

CVE-2017-5101
Luan Herrera discovered a URL spoofing issue.

CVE-2017-5102
An uninitialized variable was discovered in the skia library.

CVE-2017-5103
Another uninitialized variable was discovered in the skia library.

CVE-2017-5104
Khalil Zhani discovered a user interface spoofing issue.

CVE-2017-5105
Rayyan Bijoora discovered a URL spoofing issue.

CVE-2017-5106
Jack Zac discovered a URL spoofing issue.

CVE-2017-5107
David Kohlbrenner discovered an information leak in SVG file handling.

CVE-2017-5108
Guang Gong discovered a type confusion issue in the pdfium library.

CVE-2017-5109
Jose Maria Acuna Morgado discovered a user interface spoofing issue.

CVE-2017-5110
xisigr discovered a way to spoof the payments dialog.

CVE-2017-7000
Chaitin Security Research Lab discovered an information disclosure
issue in the sqlite library." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "60.0.3112.78-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "60.0.3112.78-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-driver", ver: "60.0.3112.78-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "60.0.3112.78-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-shell", ver: "60.0.3112.78-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-widevine", ver: "60.0.3112.78-1~deb9u1", rls: "DEB9" ) ) != NULL){
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

