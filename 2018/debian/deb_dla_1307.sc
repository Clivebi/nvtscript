if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891307" );
	script_version( "2021-06-16T02:00:28+0000" );
	script_cve_id( "CVE-2018-0202", "CVE-2018-1000085" );
	script_name( "Debian LTS: Security Advisory for clamav (DLA-1307-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:00:28 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-26 16:02:00 +0000 (Tue, 26 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/03/msg00011.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "clamav on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.99.4+dfsg-1+deb7u1.

We recommend that you upgrade your clamav packages." );
	script_tag( name: "summary", value: "Some vulnerabilities have been found in ClamAV, an open source antivirus
engine:

CVE-2018-0202

It was found that ClamAV didn't process certain PDF files correctly,
relating to a heap overflow. Specially crafted PDFs could yield ClamAV
to crash, resulting in a denial-of-service or potentially execution of
arbitrary code.

CVE-2018-1000085

Hanno B?ck discovered that ClamAV didn't process XAR files correctly.
Malformed XAR files could cause ClamAV to crash by an out of bounds
heap read. This could result in a denial-of-service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "clamav", ver: "0.99.4+dfsg-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-base", ver: "0.99.4+dfsg-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-daemon", ver: "0.99.4+dfsg-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-dbg", ver: "0.99.4+dfsg-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-docs", ver: "0.99.4+dfsg-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-freshclam", ver: "0.99.4+dfsg-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-milter", ver: "0.99.4+dfsg-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-testfiles", ver: "0.99.4+dfsg-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libclamav-dev", ver: "0.99.4+dfsg-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libclamav7", ver: "0.99.4+dfsg-1+deb7u1", rls: "DEB7" ) )){
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

