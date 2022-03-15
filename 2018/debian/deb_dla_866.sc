if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890866" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2017-5029" );
	script_name( "Debian LTS: Security Advisory for libxslt (DLA-866-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-12 00:00:00 +0100 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/03/msg00023.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libxslt on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', this problem has been fixed in version
1.1.26-14.1+deb7u3.

We recommend that you upgrade your libxslt packages." );
	script_tag( name: "summary", value: "libxslt is vulnerable to an integer overflow in the xsltAddTextString
function that can be exploited to trigger an out of bounds write on 64-bit
systems." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxslt1-dbg", ver: "1.1.26-14.1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxslt1-dev", ver: "1.1.26-14.1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxslt1.1", ver: "1.1.26-14.1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxslt1", ver: "1.1.26-14.1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxslt1-dbg", ver: "1.1.26-14.1+deb7u3", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xsltproc", ver: "1.1.26-14.1+deb7u3", rls: "DEB7" ) )){
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

