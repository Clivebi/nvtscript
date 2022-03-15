if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704340" );
	script_version( "2021-06-16T02:47:07+0000" );
	script_cve_id( "CVE-2018-17478" );
	script_name( "Debian Security Advisory DSA 4340-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:47:07 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-18 00:00:00 +0100 (Sun, 18 Nov 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-28 16:25:00 +0000 (Fri, 28 Jun 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4340.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 70.0.3538.102-1~deb9u1.

We recommend that you upgrade your chromium-browser packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/chromium-browser" );
	script_tag( name: "summary", value: "An out-of-bounds bounds memory access issue was discovered in chromium's
v8 javascript library by cloudfuzzer.

This update also fixes two problems introduced by the previous security
upload. Support for arm64 has been restored and gconf-service is no longer
a package dependency." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "chromedriver", ver: "70.0.3538.102-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium", ver: "70.0.3538.102-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-driver", ver: "70.0.3538.102-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-l10n", ver: "70.0.3538.102-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-shell", ver: "70.0.3538.102-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-widevine", ver: "70.0.3538.102-1~deb9u1", rls: "DEB9" ) )){
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

