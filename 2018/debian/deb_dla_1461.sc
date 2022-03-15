if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891461" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2018-0360", "CVE-2018-0361" );
	script_name( "Debian LTS: Security Advisory for clamav (DLA-1461-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-26 00:00:00 +0200 (Sun, 26 Aug 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-26 16:41:00 +0000 (Fri, 26 Apr 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00020.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "clamav on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.100.1+dfsg-0+deb8u1.

We recommend that you upgrade your clamav packages." );
	script_tag( name: "summary", value: "ClamAV, an anti-virus utility for Unix, has released the version 0.100.1.
Installing this new version is required to make use of all current virus
signatures and to avoid warnings.

This version also fixes two security issues discovered after version 0.100.0:

CVE-2018-0360

Integer overflow with a resultant infinite loop via a crafted Hangul Word
Processor file. Reported by Secunia Research at Flexera.

CVE-2018-0361

PDF object length check, unreasonably long time to parse a relatively small
file. Reported by aCaB." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "clamav", ver: "0.100.1+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-base", ver: "0.100.1+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-daemon", ver: "0.100.1+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-dbg", ver: "0.100.1+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-docs", ver: "0.100.1+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-freshclam", ver: "0.100.1+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-milter", ver: "0.100.1+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-testfiles", ver: "0.100.1+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamdscan", ver: "0.100.1+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libclamav-dev", ver: "0.100.1+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libclamav7", ver: "0.100.1+dfsg-0+deb8u1", rls: "DEB8" ) )){
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

