if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891302" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2018-3836", "CVE-2018-7186", "CVE-2018-7440" );
	script_name( "Debian LTS: Security Advisory for leptonlib (DLA-1302-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00005.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "leptonlib on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.69-3.1+deb7u2.

We recommend that you upgrade your leptonlib packages." );
	script_tag( name: "summary", value: "Different flaws have been found in leptonlib, an image processing
library.

CVE-2018-7186

Leptonica did not limit the number of characters in a %s format
argument to fscanf or sscanf, that made it possible to remote
attackers to cause a denial of service (stack-based buffer overflow)
or possibly have unspecified other impact via a long string.

CVE-2018-7440

The gplotMakeOutput function allowed command injection via a
$(command) approach in the gplot rootname argument. This issue
existed because of an incomplete fix for CVE-2018-3836." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "leptonica-progs", ver: "1.69-3.1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblept3", ver: "1.69-3.1+deb7u2", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libleptonica-dev", ver: "1.69-3.1+deb7u2", rls: "DEB7" ) )){
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

