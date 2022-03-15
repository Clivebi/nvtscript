if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704404" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-5786" );
	script_name( "Debian Security Advisory DSA 4404-1 (chromium - security update)" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-09 00:00:00 +0100 (Sat, 09 Mar 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-01 18:26:00 +0000 (Mon, 01 Jul 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4404.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "chromium on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 72.0.3626.122-1~deb9u1.

We recommend that you upgrade your chromium packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/chromium" );
	script_tag( name: "summary", value: "Clement Lecigne discovered a use-after-free issue in chromium's file
reader implementation. A maliciously crafted file could be used to
remotely execute arbitrary code because of this problem.

This update also fixes a regression introduced in a previous update. The
browser would always crash when launched in remote debugging mode." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "chromedriver", ver: "72.0.3626.122-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium", ver: "72.0.3626.122-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-driver", ver: "72.0.3626.122-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-l10n", ver: "72.0.3626.122-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-shell", ver: "72.0.3626.122-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "chromium-widevine", ver: "72.0.3626.122-1~deb9u1", rls: "DEB9" ) )){
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

