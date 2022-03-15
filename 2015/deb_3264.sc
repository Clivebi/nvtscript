if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703264" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2015-0797", "CVE-2015-2708", "CVE-2015-2710", "CVE-2015-2713", "CVE-2015-2716" );
	script_name( "Debian Security Advisory DSA 3264-1 (icedove - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-05-19 00:00:00 +0200 (Tue, 19 May 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3264.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "icedove on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 31.7.0-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 31.7.0-1~deb8u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your icedove packages." );
	script_tag( name: "summary", value: "Multiple security issues have
been found in Icedove, Debian's version of the Mozilla Thunderbird mail client:
Multiple memory safety errors, buffer overflows and use-after-frees may lead to
the execution of arbitrary code, privilege escalation or denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "calendar-google-provider", ver: "31.7.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove", ver: "31.7.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dbg", ver: "31.7.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dev", ver: "31.7.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceowl-extension", ver: "31.7.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

