if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704058" );
	script_version( "2021-09-14T09:01:51+0000" );
	script_cve_id( "CVE-2017-1000229", "CVE-2017-16938" );
	script_name( "Debian Security Advisory DSA 4058-1 (optipng - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 09:01:51 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-08 00:00:00 +0100 (Fri, 08 Dec 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-06 19:29:00 +0000 (Mon, 06 May 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4058.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "optipng on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 0.7.5-1+deb8u2.

For the stable distribution (stretch), these problems have been fixed in
version 0.7.6-1+deb9u1.

We recommend that you upgrade your optipng packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/optipng" );
	script_tag( name: "summary", value: "Two vulnerabilities were discovered in optipng, an advanced PNG
optimizer, which may result in denial of service or the execution of
arbitrary code if a malformed file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "optipng", ver: "0.7.5-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "optipng", ver: "0.7.6-1+deb9u1", rls: "DEB9" ) )){
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

