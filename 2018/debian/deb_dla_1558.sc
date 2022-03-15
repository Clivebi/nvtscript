if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891558" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2018-16395", "CVE-2018-16396" );
	script_name( "Debian LTS: Security Advisory for ruby2.1 (DLA-1558-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-29 00:00:00 +0100 (Mon, 29 Oct 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/10/msg00020.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "ruby2.1 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.1.5-2+deb8u6.

We recommend that you upgrade your ruby2.1 packages." );
	script_tag( name: "summary", value: "CVE-2018-16395
Fix for OpenSSL::X509::Name equality check.

CVE-2018-16396
Tainted flags are not propagated in Array#pack and String#unpack
with some directives." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libruby2.1", ver: "2.1.5-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1", ver: "2.1.5-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1-dev", ver: "2.1.5-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1-doc", ver: "2.1.5-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ruby2.1-tcltk", ver: "2.1.5-2+deb8u6", rls: "DEB8" ) )){
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

