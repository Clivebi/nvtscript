if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890863" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2017-7178" );
	script_name( "Debian LTS: Security Advisory for deluge (DLA-863-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-12 00:00:00 +0100 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-08 17:40:00 +0000 (Wed, 08 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/03/msg00020.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "deluge on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', this issue has been fixed in deluge version
1.3.3-2+nmu1+deb7u1.

We recommend that you upgrade your deluge packages." );
	script_tag( name: "summary", value: "It was discovered that there was a cross-site request forgery vulnerability in
the WebUI component of the 'deluge' Bittorrent client." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "deluge", ver: "1.3.3-2+nmu1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "deluge-common", ver: "1.3.3-2+nmu1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "deluge-console", ver: "1.3.3-2+nmu1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "deluge-gtk", ver: "1.3.3-2+nmu1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "deluge-torrent", ver: "1.3.3-2+nmu1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "deluge-web", ver: "1.3.3-2+nmu1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "deluge-webui", ver: "1.3.3-2+nmu1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "deluged", ver: "1.3.3-2+nmu1+deb7u1", rls: "DEB7" ) )){
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

