if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891279" );
	script_version( "2021-06-21T02:00:27+0000" );
	script_cve_id( "CVE-2017-11423", "CVE-2017-6419" );
	script_name( "Debian LTS: Security Advisory for clamav (DLA-1279-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-21 00:00:00 +0100 (Wed, 21 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/02/msg00014.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "clamav on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.99.2+dfsg-0+deb7u5.

We recommend that you upgrade your clamav packages." );
	script_tag( name: "summary", value: "CVE-2017-6419
CVE-2017-11423

Two vulnerabilities have been fixed that can be used for denial of
service or maybe unspecified impact via drafted files
(heap-based buffer overflow and stack-based buffer over-read causing
application crash)" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "clamav", ver: "0.99.2+dfsg-0+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-base", ver: "0.99.2+dfsg-0+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-daemon", ver: "0.99.2+dfsg-0+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-dbg", ver: "0.99.2+dfsg-0+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-docs", ver: "0.99.2+dfsg-0+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-freshclam", ver: "0.99.2+dfsg-0+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-milter", ver: "0.99.2+dfsg-0+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "clamav-testfiles", ver: "0.99.2+dfsg-0+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libclamav-dev", ver: "0.99.2+dfsg-0+deb7u5", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libclamav7", ver: "0.99.2+dfsg-0+deb7u5", rls: "DEB7" ) )){
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

