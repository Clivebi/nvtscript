if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703692" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-3885", "CVE-2016-5684" );
	script_name( "Debian Security Advisory DSA 3692-1 (freeimage - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-10-13 00:00:00 +0200 (Thu, 13 Oct 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3692.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "freeimage on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 3.15.4-4.2+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 3.17.0+ds1-3.

For the unstable distribution (sid), these problems have been fixed in
version 3.17.0+ds1-3.

We recommend that you upgrade your freeimage packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered in the FreeImage multimedia
library, which might result in denial of service or the execution of
arbitrary code if a malformed XMP or RAW image is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libfreeimage-dev", ver: "3.17.0+ds1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeimage3", ver: "3.17.0+ds1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeimage3-dbg", ver: "3.17.0+ds1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeimageplus-dev", ver: "3.17.0+ds1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeimageplus-doc", ver: "3.17.0+ds1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeimageplus3", ver: "3.17.0+ds1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeimageplus3-dbg", ver: "3.17.0+ds1-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeimage-dev", ver: "3.15.4-4.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeimage3", ver: "3.15.4-4.2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfreeimage3-dbg", ver: "3.15.4-4.2+deb8u1", rls: "DEB8" ) ) != NULL){
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

