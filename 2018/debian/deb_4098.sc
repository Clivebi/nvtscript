if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704098" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-1000005", "CVE-2018-1000007" );
	script_name( "Debian Security Advisory DSA 4098-1 (curl - security update)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-26 00:00:00 +0100 (Fri, 26 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-18 22:15:00 +0000 (Tue, 18 Jun 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4098.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "curl on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 7.38.0-4+deb8u9.

For the stable distribution (stretch), these problems have been fixed in
version 7.52.1-5+deb9u4.

We recommend that you upgrade your curl packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/curl" );
	script_tag( name: "summary", value: "Two vulnerabilities were discovered in cURL, an URL transfer library.

CVE-2018-1000005
Zhouyihai Ding discovered an out-of-bounds read in the code
handling HTTP/2 trailers. This issue doesn't affect the oldstable
distribution (jessie).

CVE-2018-1000007
Craig de Stigter discovered that authentication data might be leaked
to third parties when following HTTP redirects." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.38.0-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3", ver: "7.38.0-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.38.0-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.38.0-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.38.0-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-doc", ver: "7.38.0-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.38.0-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.38.0-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.38.0-4+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "curl", ver: "7.52.1-5+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3", ver: "7.52.1-5+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.52.1-5+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.52.1-5+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.52.1-5+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-doc", ver: "7.52.1-5+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.52.1-5+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.52.1-5+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.52.1-5+deb9u4", rls: "DEB9" ) )){
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

