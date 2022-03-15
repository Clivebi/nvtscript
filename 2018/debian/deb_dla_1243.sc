if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891243" );
	script_version( "2021-06-21T02:00:27+0000" );
	script_cve_id( "CVE-2017-8314" );
	script_name( "Debian LTS: Security Advisory for xbmc (DLA-1243-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-16 00:00:00 +0100 (Tue, 16 Jan 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/01/msg00019.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "xbmc on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2:11.0~git20120510.82388d5-1+deb7u1.

We recommend that you upgrade your xbmc packages." );
	script_tag( name: "summary", value: "The Check Point Research Team discovered that the XBMC media center
allows arbitrary file write when a malicious subtitle file is
downloaded in zip format. This update requires the new dependency
libboost-regex1.49." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "xbmc", ver: "2:11.0~git20120510.82388d5-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xbmc-bin", ver: "2:11.0~git20120510.82388d5-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xbmc-data", ver: "2:11.0~git20120510.82388d5-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xbmc-eventclients-common", ver: "2:11.0~git20120510.82388d5-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xbmc-eventclients-dev", ver: "2:11.0~git20120510.82388d5-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xbmc-eventclients-j2me", ver: "2:11.0~git20120510.82388d5-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xbmc-eventclients-ps3", ver: "2:11.0~git20120510.82388d5-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xbmc-eventclients-wiiremote", ver: "2:11.0~git20120510.82388d5-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xbmc-eventclients-xbmc-send", ver: "2:11.0~git20120510.82388d5-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xbmc-skin-confluence", ver: "2:11.0~git20120510.82388d5-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xbmc-standalone", ver: "2:11.0~git20120510.82388d5-1+deb7u1", rls: "DEB7" ) )){
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

