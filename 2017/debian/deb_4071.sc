if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704071" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_cve_id( "CVE-2017-17512" );
	script_name( "Debian Security Advisory DSA 4071-1 (sensible-utils - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-21 00:00:00 +0100 (Thu, 21 Dec 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4071.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "sensible-utils on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 0.0.9+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 0.0.9+deb9u1.

We recommend that you upgrade your sensible-utils packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/sensible-utils" );
	script_tag( name: "summary", value: "Gabriel Corona reported that sensible-browser from sensible-utils, a
collection of small utilities used to sensibly select and spawn an
appropriate browser, editor or pager, does not validate strings before
launching the program specified by the BROWSER environment variable,
potentially allowing a remote attacker to conduct argument-injection
attacks if a user is tricked into processing a specially crafted URL." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sensible-utils", ver: "0.0.9+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "sensible-utils", ver: "0.0.9+deb9u1", rls: "DEB9" ) )){
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

