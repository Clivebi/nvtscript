if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703710" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-9189", "CVE-2016-9190" );
	script_name( "Debian Security Advisory DSA 3710-1 (pillow - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-10 00:00:00 +0100 (Thu, 10 Nov 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3710.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "pillow on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 2.6.1-2+deb8u3.

For the testing distribution (stretch), these problems have been fixed
in version 3.4.2-1.

For the unstable distribution (sid), these problems have been fixed in
version 3.4.2-1.

We recommend that you upgrade your pillow packages." );
	script_tag( name: "summary", value: "Cris Neckar discovered multiple
vulnerabilities in Pillow, a Python imaging library, which may result in the
execution of arbitrary code or information disclosure if a malformed image
file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-imaging", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil:amd64", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil:i386", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil-dbg:amd64", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil-dbg:i386", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil-doc", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk:amd64", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk:i386", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk-dbg:amd64", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk-dbg:i386", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil:amd64", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil:i386", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil-dbg:amd64", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil-dbg:i386", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil.imagetk:amd64", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil.imagetk:i386", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil.imagetk-dbg", ver: "3.4.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-imaging", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-imaging-tk", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil:amd64", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil:i386", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil-dbg:amd64", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil-dbg:i386", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil-doc", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk:amd64", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk:i386", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk-dbg:amd64", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pil.imagetk-dbg:i386", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-sane:amd64", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-sane:i386", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-sane-dbg:amd64", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-sane-dbg:i386", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pill:amd64", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pill:i386", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil-dbg:amd64", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil-dbg:i386", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil.imagetk:amd64", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil.imagetk:i386", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pil.imagetk-dbg", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-sane:amd64", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-sane:i386", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-sane-dbg:amd64", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-sane-dbg:i386", ver: "2.6.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
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

