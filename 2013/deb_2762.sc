if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702762" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1722", "CVE-2013-1730", "CVE-2013-1737", "CVE-2013-1718", "CVE-2013-1732", "CVE-2013-1736", "CVE-2013-1735", "CVE-2013-1725" );
	script_name( "Debian Security Advisory DSA 2762-1 (icedove - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-23 00:00:00 +0200 (Mon, 23 Sep 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2762.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "icedove on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 17.0.9-1~deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your icedove packages." );
	script_tag( name: "summary", value: "Multiple security issues have been found in Icedove, Debian's version of
the Mozilla Thunderbird mail and news client. Multiple memory safety
errors and buffer overflows may lead to the execution of arbitrary code.

The Icedove version in the oldstable distribution (squeeze) is no longer
supported with full security updates. However, it should be noted that
almost all security issues in Icedove stem from the included browser engine.
These security problems only affect Icedove if scripting and HTML mails
are enabled. If there are security issues specific to Icedove (e.g. a
hypothetical buffer overflow in the IMAP implementation) we'll make an
effort to backport such fixes to oldstable." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "calendar-google-provider", ver: "17.0.9-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "calendar-timezones", ver: "17.0.9-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove", ver: "17.0.9-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dbg", ver: "17.0.9-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dev", ver: "17.0.9-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceowl-extension", ver: "17.0.9-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

