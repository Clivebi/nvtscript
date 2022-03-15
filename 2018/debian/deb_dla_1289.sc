if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891289" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2018-7050", "CVE-2018-7051", "CVE-2018-7052" );
	script_name( "Debian LTS: Security Advisory for irssi (DLA-1289-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-28 18:39:00 +0000 (Thu, 28 Feb 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/02/msg00024.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "irssi on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these issues have been fixed in irssi version
0.8.15-5+deb7u5.

We recommend that you upgrade your irssi packages." );
	script_tag( name: "summary", value: "It was discovered that there where a number of vulnerabilities in irssi,
the terminal based IRC client:

  - CVE-2018-7050: Null pointer dereference for an 'empty' nick.

  - CVE-2018-7051: Certain nick names could result in out-of-bounds
    access when printing theme strings.

  - CVE-2018-7052: When the number of windows exceeds the available space, a
    crash could occur due to another NULL pointer dereference." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "irssi", ver: "0.8.15-5+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "irssi-dev", ver: "0.8.15-5+deb7u5", rls: "DEB7" ) )){
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

