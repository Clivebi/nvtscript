if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890979" );
	script_version( "2020-01-29T08:33:43+0000" );
	script_name( "Debian LTS: Security Advisory for debian-security-support (DLA-979-1)" );
	script_tag( name: "last_modification", value: "2020-01-29 08:33:43 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "creation_date", value: "2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/06/msg00010.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "debian-security-support on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2017.06.02+deb7u1.

We recommend that you upgrade your debian-security-support packages." );
	script_tag( name: "summary", value: "Besides bringing the package up to date regarding translations this
update marks several packages as no longer supported by wheezy-lts:

autotrace, inspircd, ioquake3, kfreebsd-8, kfreebsd-9, matrixssl,
teeworlds and trn

For the reasoning please see the links provided in

/usr/share/debian-security-support/security-support-ended.deb8" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "debian-security-support", ver: "2017.06.02+deb7u1", rls: "DEB7" ) )){
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

