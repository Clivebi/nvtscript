if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704344" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2018-19206" );
	script_name( "Debian Security Advisory DSA 4344-1 (roundcube - security update)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-24 00:00:00 +0100 (Sat, 24 Nov 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-13 13:02:00 +0000 (Thu, 13 Dec 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4344.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "roundcube on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.2.3+dfsg.1-4+deb9u3.

We recommend that you upgrade your roundcube packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/roundcube" );
	script_tag( name: "summary", value: "Aidan Marlin discovered that roundcube, a skinnable AJAX based webmail
solution for IMAP servers, is prone to a cross-site scripting
vulnerability in handling invalid style tag content." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "roundcube", ver: "1.2.3+dfsg.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-core", ver: "1.2.3+dfsg.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-mysql", ver: "1.2.3+dfsg.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-pgsql", ver: "1.2.3+dfsg.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-plugins", ver: "1.2.3+dfsg.1-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "roundcube-sqlite3", ver: "1.2.3+dfsg.1-4+deb9u3", rls: "DEB9" ) )){
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

