if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704858" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-21148", "CVE-2021-21149", "CVE-2021-21150", "CVE-2021-21151", "CVE-2021-21152", "CVE-2021-21153", "CVE-2021-21154", "CVE-2021-21155", "CVE-2021-21156", "CVE-2021-21157" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-17 19:56:00 +0000 (Mon, 17 May 2021)" );
	script_tag( name: "creation_date", value: "2021-02-21 04:00:11 +0000 (Sun, 21 Feb 2021)" );
	script_name( "Debian: Security Advisory for chromium (DSA-4858-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4858.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4858-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4858-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-4858-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2021-21148
Mattias Buelens discovered a buffer overflow issue in the v8 javascript
library.

CVE-2021-21149
Ryoya Tsukasaki discovered a stack overflow issue in the Data Transfer
implementation.

CVE-2021-21150
Woojin Oh discovered a use-after-free issue in the file downloader.

CVE-2021-21151
Khalil Zhani discovered a use-after-free issue in the payments system.

CVE-2021-21152
A buffer overflow was discovered in media handling.

CVE-2021-21153
Jan Ruge discovered a stack overflow issue in the GPU process.

CVE-2021-21154
Abdulrahman Alqabandi discovered a buffer overflow issue in the Tab Strip
implementation.

CVE-2021-21155
Khalil Zhani discovered a buffer overflow issue in the Tab Strip
implementation.

CVE-2021-21156
Sergei Glazunov discovered a buffer overflow issue in the v8 javascript
library.

CVE-2021-21157
A use-after-free issue was discovered in the Web Sockets implementation." );
	script_tag( name: "affected", value: "'chromium' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 88.0.4324.182-1~deb10u1.

We recommend that you upgrade your chromium packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "chromium", ver: "88.0.4324.182-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-common", ver: "88.0.4324.182-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-driver", ver: "88.0.4324.182-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-l10n", ver: "88.0.4324.182-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-sandbox", ver: "88.0.4324.182-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-shell", ver: "88.0.4324.182-1~deb10u1", rls: "DEB10" ) )){
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

