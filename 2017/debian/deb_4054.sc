if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704054" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-8819", "CVE-2017-8820", "CVE-2017-8821", "CVE-2017-8822", "CVE-2017-8823" );
	script_name( "Debian Security Advisory DSA 4054-1 (tor - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-03 00:00:00 +0100 (Sun, 03 Dec 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-21 18:01:00 +0000 (Thu, 21 Dec 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4054.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "tor on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 0.2.5.16-1.

For the stable distribution (stretch), these problems have been fixed in
version 0.2.9.14-1.

We recommend that you upgrade your tor packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/tor" );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been found in Tor, a connection-based
low-latency anonymous communication system." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "tor", ver: "0.2.9.14-1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tor-dbg", ver: "0.2.9.14-1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tor-geoipdb", ver: "0.2.9.14-1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tor", ver: "0.2.5.16-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tor-dbg", ver: "0.2.5.16-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tor-geoipdb", ver: "0.2.5.16-1", rls: "DEB8" ) )){
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

