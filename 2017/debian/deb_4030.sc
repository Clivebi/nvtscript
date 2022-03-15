if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704030" );
	script_version( "2021-09-14T09:01:51+0000" );
	script_cve_id( "CVE-2017-16651" );
	script_name( "Debian Security Advisory DSA 4030-1 (roundcube - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 09:01:51 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-09 00:00:00 +0100 (Thu, 09 Nov 2017)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 21:08:00 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4030.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "roundcube on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.2.3+dfsg.1-4+deb9u1.

For the unstable distribution (sid), this problem has been fixed in
version 1.3.3+dfsg.1-1.

We recommend that you upgrade your roundcube packages." );
	script_tag( name: "summary", value: "A file disclosure vulnerability was discovered in roundcube, a skinnable
AJAX based webmail solution for IMAP servers. An authenticated attacker
can take advantage of this flaw to read roundcube's configuration files." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "roundcube", ver: "1.2.3+dfsg.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-core", ver: "1.2.3+dfsg.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-mysql", ver: "1.2.3+dfsg.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-pgsql", ver: "1.2.3+dfsg.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-plugins", ver: "1.2.3+dfsg.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "roundcube-sqlite3", ver: "1.2.3+dfsg.1-4+deb9u1", rls: "DEB9" ) ) != NULL){
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

