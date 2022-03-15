if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892408" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-15673", "CVE-2020-15676", "CVE-2020-15677", "CVE-2020-15678" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-10-17 03:00:12 +0000 (Sat, 17 Oct 2020)" );
	script_name( "Debian LTS: Security Advisory for thunderbird (DLA-2408-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/10/msg00020.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2408-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the DLA-2408-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues have been found in Thunderbird, which may lead
to the execution of arbitrary code or denial of service.

Debian follows the Thunderbird upstream releases. Support for the 68.x
series has ended, so starting with this update we're now following
the 78.x releases.

The 78.x series discontinues support for some addons. Also, starting
with 78, Thunderbird supports OpenPGP natively. If you are currently
using the Enigmail addon for PGP, please refer to the included NEWS
and README.Debian.gz files for information on how to migrate your
keys." );
	script_tag( name: "affected", value: "'thunderbird' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1:78.3.1-2~deb9u1.

We recommend that you upgrade your thunderbird packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "calendar-google-provider", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-dbg", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-dev", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-all", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-ar", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-ast", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-be", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-bg", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-bn-bd", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-br", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-ca", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-cs", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-da", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-de", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-dsb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-el", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-en-gb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-es-ar", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-es-es", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-et", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-eu", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-fi", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-fr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-fy-nl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-ga-ie", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-gd", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-gl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-he", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-hr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-hsb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-hu", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-hy-am", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-id", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-is", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-it", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-ja", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-kab", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-ko", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-lt", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-nb-no", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-nl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-nn-no", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-pa-in", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-pl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-pt-br", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-pt-pt", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-rm", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-ro", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-ru", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-si", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-sk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-sl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-sq", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-sr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-sv-se", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-ta-lk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-tr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-uk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-vi", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-zh-cn", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "icedove-l10n-zh-tw", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-extension", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-ar", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-ast", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-be", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-bg", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-bn-bd", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-br", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-ca", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-cs", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-cy", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-da", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-de", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-dsb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-el", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-en-gb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-es-ar", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-es-es", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-et", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-eu", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-fi", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-fr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-fy-nl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-ga-ie", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-gd", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-gl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-he", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-hr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-hsb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-hu", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-hy-am", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-id", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-is", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-it", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-ja", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-kab", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-ko", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-lt", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-nb-no", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-nl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-nn-no", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-pa-in", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-pl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-pt-br", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-pt-pt", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-rm", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-ro", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-ru", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-si", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-sk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-sl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-sq", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-sr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-sv-se", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-ta-lk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-tr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-uk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-vi", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-zh-cn", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceowl-l10n-zh-tw", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ar", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ast", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-be", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-bg", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-bn-bd", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-br", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ca", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-cs", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-cy", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-da", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-de", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-dsb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-el", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-en-gb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-es-ar", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-es-es", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-et", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-eu", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-fi", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-fr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-fy-nl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ga-ie", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-gd", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-gl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-he", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-hr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-hsb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-hu", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-hy-am", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-id", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-is", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-it", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ja", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-kab", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-kk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ko", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-lt", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ms", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-nb-no", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-nl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-nn-no", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-pa-in", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-pl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-pt-br", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-pt-pt", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-rm", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ro", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ru", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-si", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-sk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-sl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-sq", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-sr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-sv-se", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ta-lk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-tr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-uk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-vi", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-zh-cn", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-zh-tw", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-dbg", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-dev", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-all", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ar", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ast", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-be", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-bg", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-bn-bd", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-br", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ca", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-cs", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-cy", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-da", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-de", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-dsb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-el", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-en-gb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-es-ar", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-es-es", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-et", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-eu", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-fi", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-fr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-fy-nl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ga-ie", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-gd", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-gl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-he", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-hr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-hsb", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-hu", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-hy-am", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-id", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-is", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-it", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ja", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-kab", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-kk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ko", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-lt", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ms", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-nb-no", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-nl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-nn-no", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-pa-in", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-pl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-pt-br", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-pt-pt", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-rm", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ro", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ru", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-si", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-sk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-sl", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-sq", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-sr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-sv-se", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ta-lk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-tr", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-uk", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-vi", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-zh-cn", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-zh-tw", ver: "1:78.3.1-2~deb9u1", rls: "DEB9" ) )){
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
