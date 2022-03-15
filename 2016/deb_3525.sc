if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703525" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2014-9766" );
	script_name( "Debian Security Advisory DSA 3525-1 (pixman - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-03-22 00:00:00 +0100 (Tue, 22 Mar 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-03 03:02:00 +0000 (Sat, 03 Dec 2016)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3525.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "pixman on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 0.26.0-4+deb7u2.

For the stable distribution (jessie), the testing distribution (stretch)
and the unstable distribution (sid), this problem was already fixed in
version 0.32.6-1.

We recommend that you upgrade your pixman packages." );
	script_tag( name: "summary", value: "Vincent LE GARREC discovered an integer
overflow in pixman, a pixel-manipulation library for X and cairo. A remote attacker
can exploit this flaw to cause an application using the pixman library to
crash, or potentially, to execute arbitrary code with the privileges of
the user running the application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpixman-1-0:amd64", ver: "0.26.0-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpixman-1-0:i386", ver: "0.26.0-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpixman-1-0-dbg:amd64", ver: "0.26.0-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpixman-1-0-dbg:i386", ver: "0.26.0-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpixman-1-dev", ver: "0.26.0-4+deb7u2", rls: "DEB7" ) ) != NULL){
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

