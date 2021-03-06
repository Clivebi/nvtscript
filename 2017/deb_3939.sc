if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703939" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_cve_id( "CVE-2017-2801" );
	script_name( "Debian Security Advisory DSA 3939-1 (botan1.10 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-12 00:00:00 +0200 (Sat, 12 Aug 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3939.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "botan1.10 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.10.8-2+deb8u2.

For the stable distribution (stretch), this problem has been fixed
prior to the initial release.

We recommend that you upgrade your botan1.10 packages." );
	script_tag( name: "summary", value: "Aleksandar Nikolic discovered that an error in the x509 parser of the
Botan crypto library could result in an out-of-bounds memory read,
resulting in denial of service or an information leak if processing
a malformed certificate." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "botan1.10-dbg", ver: "1.10.8-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbotan-1.10-0", ver: "1.10.8-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbotan1.10-dev", ver: "1.10.8-2+deb8u2", rls: "DEB8" ) ) != NULL){
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

