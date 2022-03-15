if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703836" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_cve_id( "CVE-2017-8073" );
	script_name( "Debian Security Advisory DSA 3836-1 (weechat - security update)" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-27 00:00:00 +0200 (Thu, 27 Apr 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-16 17:15:00 +0000 (Mon, 16 Mar 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3836.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "weechat on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 1.0.1-1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 1.7-3.

We recommend that you upgrade your weechat packages." );
	script_tag( name: "summary", value: "It was discovered that weechat, a fast and light chat client, is prone
to a buffer overflow vulnerability in the IRC plugin, allowing a remote
attacker to cause a denial-of-service by sending a specially crafted
filename via DCC." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "weechat", ver: "1.0.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "weechat-core", ver: "1.0.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "weechat-curses", ver: "1.0.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "weechat-dbg", ver: "1.0.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "weechat-dev", ver: "1.0.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "weechat-doc", ver: "1.0.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "weechat-plugins", ver: "1.0.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

