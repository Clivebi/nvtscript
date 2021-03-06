if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703499" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-0740", "CVE-2016-0775", "CVE-2016-2533" );
	script_name( "Debian Security Advisory DSA 3499-1 (pillow - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-08 12:38:01 +0530 (Tue, 08 Mar 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3499.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|7|8)" );
	script_tag( name: "affected", value: "pillow on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 1.1.7-4+deb7u2 of the python-imaging source package.

For the stable distribution (jessie), this problem has been fixed in
version 2.6.1-2+deb8u2.

For the testing distribution (stretch), this problem has been fixed
in version 3.1.1-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.1.1-1.

We recommend that you upgrade your pillow packages." );
	script_tag( name: "summary", value: "Multiple security vulnerabilities have been found in Pillow, a Python
imaging library, which may result in denial of service or the execution
of arbitrary code if a malformed FLI, PCD or Tiff files is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-imaging", ver: "3.1.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil", ver: "3.1.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil-dbg", ver: "3.1.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil-doc", ver: "3.1.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk", ver: "3.1.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk-dbg", ver: "3.1.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil", ver: "3.1.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil-dbg", ver: "3.1.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil.imagetk", ver: "3.1.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil.imagetk-dbg", ver: "3.1.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-imaging", ver: "1.1.7-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-imaging-dbg", ver: "1.1.7-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-imaging-doc", ver: "1.1.7-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-imaging-sane", ver: "1.1.7-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-imaging-sane-dbg", ver: "1.1.7-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-imaging-tk", ver: "1.1.7-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-imaging-tk-dbg", ver: "1.1.7-4+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-imaging", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-imaging-tk", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil-dbg", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil-doc", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk-dbg", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-sane", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-sane-dbg", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil-dbg", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil.imagetk", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil.imagetk-dbg", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-sane", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-sane-dbg", ver: "2.6.1-2+deb8u2", rls: "DEB8" ) ) != NULL){
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

