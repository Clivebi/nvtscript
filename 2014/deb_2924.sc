if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702924" );
	script_version( "2020-08-11T09:13:39+0000" );
	script_cve_id( "CVE-2014-1518", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532" );
	script_name( "Debian Security Advisory DSA 2924-1 (icedove - security update)" );
	script_tag( name: "last_modification", value: "2020-08-11 09:13:39 +0000 (Tue, 11 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-05-05 00:00:00 +0200 (Mon, 05 May 2014)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2924.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "icedove on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 24.5.0-1~deb7u1.

For the testing distribution (jessie), these problems have been fixed in
version 24.5.0-1.

For the unstable distribution (sid), these problems have been fixed in
version 24.5.0-1.

We recommend that you upgrade your icedove packages." );
	script_tag( name: "summary", value: "Multiple security issues have been found in Icedove, Debian's version
of the Mozilla Thunderbird mail and news client: multiple memory safety
errors, buffer overflows, missing permission checks, out of bound reads,
use-after-frees and other implementation errors may lead to the
execution of arbitrary code, privilege escalation, cross-site scripting
or denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "calendar-google-provider", ver: "24.5.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "calendar-timezones", ver: "24.5.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove", ver: "24.5.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dbg", ver: "24.5.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dev", ver: "24.5.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceowl-extension", ver: "24.5.0-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

