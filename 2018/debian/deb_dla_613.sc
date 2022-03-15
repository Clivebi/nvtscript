if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890613" );
	script_version( "2020-01-29T08:28:43+0000" );
	script_cve_id( "CVE-2014-9587", "CVE-2015-1433", "CVE-2016-4069" );
	script_name( "Debian LTS: Security Advisory for roundcube (DLA-613-2)" );
	script_tag( name: "last_modification", value: "2020-01-29 08:28:43 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/07/msg00034.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "roundcube on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.7.2-9+deb7u8.

We recommend that you upgrade your roundcube packages." );
	script_tag( name: "summary", value: "The security update announced as DLA-613-1 caused a regression. A
missing null parameter set the $task variable in the rcmail_url()
function to a boolean value which led to service not available errors
when viewing attached images. Updated packages are now available to
correct this issue." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "roundcube", ver: "0.7.2-9+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-core", ver: "0.7.2-9+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-mysql", ver: "0.7.2-9+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-pgsql", ver: "0.7.2-9+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-plugins", ver: "0.7.2-9+deb7u8", rls: "DEB7" ) )){
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

