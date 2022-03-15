if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703873" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_cve_id( "CVE-2017-6512" );
	script_name( "Debian Security Advisory DSA 3873-1 (perl - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-05 00:00:00 +0200 (Mon, 05 Jun 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-29 20:24:00 +0000 (Wed, 29 Apr 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3873.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "perl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 5.20.2-3+deb8u7.

For the upcoming stable distribution (stretch), this problem has been
fixed in version 5.24.1-3.

For the unstable distribution (sid), this problem has been fixed in
version 5.24.1-3.

We recommend that you upgrade your perl packages." );
	script_tag( name: "summary", value: "The cPanel Security Team reported a time of check to time of use
(TOCTTOU) race condition flaw in File::Path, a core module from Perl to
create or remove directory trees. An attacker can take advantage of this
flaw to set the mode on an attacker-chosen file to an attacker-chosen
value." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libperl-dev", ver: "5.20.2-3+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libperl5.20", ver: "5.20.2-3+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl", ver: "5.20.2-3+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-base", ver: "5.20.2-3+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-debug", ver: "5.20.2-3+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-doc", ver: "5.20.2-3+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-modules", ver: "5.20.2-3+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libperl-dev", ver: "5.24.1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libperl5.24", ver: "5.24.1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl", ver: "5.24.1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-base", ver: "5.24.1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-debug", ver: "5.24.1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-doc", ver: "5.24.1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perl-modules-5.24", ver: "5.24.1-3", rls: "DEB9" ) ) != NULL){
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

