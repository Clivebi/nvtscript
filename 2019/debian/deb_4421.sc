if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704421" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-5787", "CVE-2019-5788", "CVE-2019-5789", "CVE-2019-5790", "CVE-2019-5791", "CVE-2019-5792", "CVE-2019-5793", "CVE-2019-5794", "CVE-2019-5795", "CVE-2019-5796", "CVE-2019-5797", "CVE-2019-5798", "CVE-2019-5799", "CVE-2019-5800", "CVE-2019-5802", "CVE-2019-5803" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-06 02:00:31 +0000 (Sat, 06 Apr 2019)" );
	script_name( "Debian Security Advisory DSA 4421-1 (chromium - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4421.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4421-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-4421-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2019-5787
Zhe Jin discovered a use-after-free issue.

CVE-2019-5788
Mark Brand discovered a use-after-free issue in the FileAPI
implementation.

CVE-2019-5789
Mark Brand discovered a use-after-free issue in the WebMIDI
implementation.

CVE-2019-5790
Dimitri Fourny discovered a buffer overflow issue in the v8 javascript
library.

CVE-2019-5791
Choongwoo Han discovered a type confusion issue in the v8 javascript
library.

CVE-2019-5792
pdknsk discovered an integer overflow issue in the pdfium library.

CVE-2019-5793
Jun Kokatsu discovered a permissions issue in the Extensions
implementation.

CVE-2019-5794
Juno Im of Theori discovered a user interface spoofing issue.

CVE-2019-5795
pdknsk discovered an integer overflow issue in the pdfium library.

CVE-2019-5796
Mark Brand discovered a race condition in the Extensions implementation.

CVE-2019-5797
Mark Brand discovered a race condition in the DOMStorage implementation.

CVE-2019-5798
Tran Tien Hung discovered an out-of-bounds read issue in the skia library.

CVE-2019-5799
sohalt discovered a way to bypass the Content Security Policy.

CVE-2019-5800
Jun Kokatsu discovered a way to bypass the Content Security Policy.

CVE-2019-5802
Ronni Skansing discovered a user interface spoofing issue.

CVE-2019-5803
Andrew Comminos discovered a way to bypass the Content Security Policy." );
	script_tag( name: "affected", value: "'chromium' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 73.0.3683.75-1~deb9u1.

We recommend that you upgrade your chromium packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "chromedriver", ver: "73.0.3683.75-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium", ver: "73.0.3683.75-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-driver", ver: "73.0.3683.75-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-l10n", ver: "73.0.3683.75-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-shell", ver: "73.0.3683.75-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-widevine", ver: "73.0.3683.75-1~deb9u1", rls: "DEB9" ) )){
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
exit( 0 );

