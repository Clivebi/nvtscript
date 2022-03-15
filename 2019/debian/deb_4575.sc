if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704575" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-13723", "CVE-2019-13724" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-26 12:49:44 +0000 (Tue, 26 Nov 2019)" );
	script_name( "Debian Security Advisory DSA 4575-1 (chromium - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4575.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4575-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-4575-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2019-13723
Yuxiang Li discovered a use-after-free issue in the bluetooth service.

CVE-2019-13724
Yuxiang Li discovered an out-of-bounds read issue in the bluetooth
service." );
	script_tag( name: "affected", value: "'chromium' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), security support for the chromium
package has been discontinued.

For the stable distribution (buster), these problems have been fixed in
version 78.0.3904.108-1~deb10u1.

We recommend that you upgrade your chromium packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "chromium", ver: "78.0.3904.108-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-common", ver: "78.0.3904.108-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-driver", ver: "78.0.3904.108-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-l10n", ver: "78.0.3904.108-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-sandbox", ver: "78.0.3904.108-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-shell", ver: "78.0.3904.108-1~deb10u1", rls: "DEB10" ) )){
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

