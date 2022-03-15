if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704917" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-30506", "CVE-2021-30507", "CVE-2021-30508", "CVE-2021-30509", "CVE-2021-30510", "CVE-2021-30511", "CVE-2021-30512", "CVE-2021-30513", "CVE-2021-30514", "CVE-2021-30515", "CVE-2021-30516", "CVE-2021-30517", "CVE-2021-30518", "CVE-2021-30519", "CVE-2021-30520" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-18 03:15:00 +0000 (Sun, 18 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-19 03:00:16 +0000 (Wed, 19 May 2021)" );
	script_name( "Debian: Security Advisory for chromium (DSA-4917-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4917.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4917-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4917-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-4917-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2021-30506
@retsew0x01 discovered an error in the Web App installation interface.

CVE-2021-30507
Alison Huffman discovered an error in the Offline mode.

CVE-2021-30508
Leecraso and Guang Gong discovered a buffer overflow issue in the Media
Feeds implementation.

CVE-2021-30509
David Erceg discovered an out-of-bounds write issue in the Tab Strip
implementation.

CVE-2021-30510
Weipeng Jiang discovered a race condition in the aura window manager.

CVE-2021-30511
David Erceg discovered an out-of-bounds read issue in the Tab Strip
implementation.

CVE-2021-30512
ZhanJia Song discovered a use-after-free issue in the notifications
implementation.

CVE-2021-30513
Man Yue Mo discovered an incorrect type in the v8 javascript library.

CVE-2021-30514
koocola and Wang discovered a use-after-free issue in the Autofill
feature.

CVE-2021-30515
Rong Jian and Guang Gong discovered a use-after-free issue in the file
system access API.

CVE-2021-30516
ZhanJia Song discovered a buffer overflow issue in the browsing history.

CVE-2021-30517
Jun Kokatsu discovered a buffer overflow issue in the reader mode.

CVE-2021-30518
laural discovered use of an incorrect type in the v8 javascript library.

CVE-2021-30519
asnine discovered a use-after-free issue in the Payments feature.

CVE-2021-30520
Khalil Zhani discovered a use-after-free issue in the Tab Strip
implementation." );
	script_tag( name: "affected", value: "'chromium' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 90.0.4430.212-1~deb10u1.

We recommend that you upgrade your chromium packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "chromium", ver: "90.0.4430.212-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-common", ver: "90.0.4430.212-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-driver", ver: "90.0.4430.212-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-l10n", ver: "90.0.4430.212-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-sandbox", ver: "90.0.4430.212-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-shell", ver: "90.0.4430.212-1~deb10u1", rls: "DEB10" ) )){
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

