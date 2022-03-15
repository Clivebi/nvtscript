if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703302" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696" );
	script_name( "Debian Security Advisory DSA 3302-1 (libwmf - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-06 00:00:00 +0200 (Mon, 06 Jul 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3302.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libwmf on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 0.2.8.4-10.3+deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 0.2.8.4-10.3+deb8u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your libwmf packages." );
	script_tag( name: "summary", value: "Insufficient input sanitising
in libwmf, a library to process Windows metafile data, may result in denial of
service or the execution of arbitrary code if a malformed WMF file is opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libwmf-bin", ver: "0.2.8.4-10.3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwmf-dev", ver: "0.2.8.4-10.3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwmf-doc", ver: "0.2.8.4-10.3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwmf0.2-7:amd64", ver: "0.2.8.4-10.3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwmf0.2-7:i386", ver: "0.2.8.4-10.3+deb7u1", rls: "DEB7" ) ) != NULL){
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

