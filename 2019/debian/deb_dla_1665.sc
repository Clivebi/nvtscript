if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891665" );
	script_version( "2020-11-05T07:12:36+0000" );
	script_name( "Debian LTS: Security Advisory for netmask (DLA-1665-1)" );
	script_tag( name: "last_modification", value: "2020-11-05 07:12:36 +0000 (Thu, 05 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-02-07 00:00:00 +0100 (Thu, 07 Feb 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00010.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1665-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "netmask on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.3.12+deb8u1.

We recommend that you upgrade your netmask packages." );
	script_tag( name: "summary", value: "buffer overflow was found in netmask which would crash when called
with arbitrarily long inputs." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "netmask", ver: "2.3.12+deb8u1", rls: "DEB8" ) )){
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

