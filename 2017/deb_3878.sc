if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703878" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2017-5974", "CVE-2017-5975", "CVE-2017-5976", "CVE-2017-5978", "CVE-2017-5979", "CVE-2017-5980", "CVE-2017-5981" );
	script_name( "Debian Security Advisory DSA 3878-1 (zziplib - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-12 00:00:00 +0200 (Mon, 12 Jun 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-31 14:33:00 +0000 (Wed, 31 Mar 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3878.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "zziplib on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 0.13.62-3+deb8u1.

For the upcoming stable distribution (stretch), these problems have been
fixed in version 0.13.62-3.1.

For the unstable distribution (sid), these problems have been fixed in
version 0.13.62-3.1.

We recommend that you upgrade your zziplib packages." );
	script_tag( name: "summary", value: "Agostino Sarubbo discovered multiple vulnerabilities in zziplib, a
library to access Zip archives, which could result in denial of service
and potentially the execution of arbitrary code if a malformed archive
is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libzzip-0-13", ver: "0.13.62-3.1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libzzip-dev", ver: "0.13.62-3.1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zziplib-bin", ver: "0.13.62-3.1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libzzip-0-13", ver: "0.13.62-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libzzip-dev", ver: "0.13.62-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zziplib-bin", ver: "0.13.62-3+deb8u1", rls: "DEB8" ) ) != NULL){
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

