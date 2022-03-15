if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891435" );
	script_version( "2020-01-29T08:28:43+0000" );
	script_name( "Debian LTS: Security Advisory for dnsmasq (DLA-1435-1)" );
	script_tag( name: "last_modification", value: "2020-01-29 08:28:43 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-07-23 00:00:00 +0200 (Mon, 23 Jul 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00027.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "dnsmasq on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.72-3+deb8u3.

We recommend that you upgrade your dnsmasq packages." );
	script_tag( name: "summary", value: "The dns-root-data update to 2017072601~deb8u2 broke dnsmasq's
init script, making dnsmasq no longer start when dns-root-data
was installed.

This update fixes dnsmasq's parsing of dns-root-data." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "dnsmasq", ver: "2.72-3+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dnsmasq-base", ver: "2.72-3+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dnsmasq-utils", ver: "2.72-3+deb8u3", rls: "DEB8" ) )){
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

