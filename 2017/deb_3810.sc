if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703810" );
	script_version( "2021-09-10T14:01:42+0000" );
	script_cve_id( "CVE-2017-5029", "CVE-2017-5030", "CVE-2017-5031", "CVE-2017-5032", "CVE-2017-5033", "CVE-2017-5034", "CVE-2017-5035", "CVE-2017-5036", "CVE-2017-5037", "CVE-2017-5038", "CVE-2017-5039", "CVE-2017-5040", "CVE-2017-5041", "CVE-2017-5042", "CVE-2017-5043", "CVE-2017-5044", "CVE-2017-5045", "CVE-2017-5046" );
	script_name( "Debian Security Advisory DSA 3810-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 14:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-15 00:00:00 +0100 (Wed, 15 Mar 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3810.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 57.0.2987.98-1~deb8u1.

For the upcoming stable (stretch) and unstable (sid) distributions, these
problems have been fixed in version 57.0.2987.98-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2017-5029
Holger Fuhrmannek discovered an integer overflow issue in the libxslt
library.

CVE-2017-5030
Brendon Tiszka discovered a memory corruption issue in the v8 javascript
library.

CVE-2017-5031
Looben Yang discovered a use-after-free issue in the ANGLE library.

CVE-2017-5032
Ashfaq Ansari discovered an out-of-bounds write in the pdfium library.

CVE-2017-5033
Nicolai Gr�dum discovered a way to bypass the Content Security Policy.

CVE-2017-5034
Ke Liu discovered an integer overflow issue in the pdfium library.

CVE-2017-5035
Enzo Aguado discovered an issue with the omnibox.

CVE-2017-5036
A use-after-free issue was discovered in the pdfium library.

CVE-2017-5037
Yongke Wang discovered multiple out-of-bounds write issues.

CVE-2017-5038
A use-after-free issue was discovered in the guest view.

CVE-2017-5039
jinmo123 discovered a use-after-free issue in the pdfium library.

CVE-2017-5040
Choongwoo Han discovered an information disclosure issue in the v8
javascript library.

CVE-2017-5041
Jordi Chancel discovered an address spoofing issue.

CVE-2017-5042
Mike Ruddy discovered incorrect handling of cookies.

CVE-2017-5043
Another use-after-free issue was discovered in the guest view.

CVE-2017-5044
Kushal Arvind Shah discovered a heap overflow issue in the skia
library.

CVE-2017-5045
Dhaval Kapil discovered an information disclosure issue.

CVE-2017-5046
Masato Kinugawa discovered an information disclosure issue." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "57.0.2987.98-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "57.0.2987.98-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-driver", ver: "57.0.2987.98-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "57.0.2987.98-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-shell", ver: "57.0.2987.98-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-widevine", ver: "57.0.2987.98-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "57.0.2987.98-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "57.0.2987.98-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "57.0.2987.98-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "57.0.2987.98-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "57.0.2987.98-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

