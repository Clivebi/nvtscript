if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704105" );
	script_version( "2021-06-17T04:16:32+0000" );
	script_cve_id( "CVE-2018-6360" );
	script_name( "Debian Security Advisory DSA 4105-1 (mpv - security update)" );
	script_tag( name: "last_modification", value: "2021-06-17 04:16:32 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-06 00:00:00 +0100 (Tue, 06 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-01 23:25:00 +0000 (Fri, 01 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4105.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "mpv on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 0.23.0-2+deb9u1.

We recommend that you upgrade your mpv packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/mpv" );
	script_tag( name: "summary", value: "It was discovered that mpv, a media player, was vulnerable to remote code
execution attacks. An attacker could craft a malicious web page that,
when used as an argument in mpv, could execute arbitrary code in the host
of the mpv user." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmpv-dev", ver: "0.23.0-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmpv1", ver: "0.23.0-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mplayer2", ver: "0.23.0-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mpv", ver: "0.23.0-2+deb9u1", rls: "DEB9" ) )){
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

