if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702813" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-3481", "CVE-2012-5576", "CVE-2013-1978", "CVE-2013-1913", "CVE-2012-3403" );
	script_name( "Debian Security Advisory DSA 2813-1 (gimp - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-12-09 00:00:00 +0100 (Mon, 09 Dec 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2813.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "gimp on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed
in version 2.6.10-1+squeeze4. This update also fixes CVE-2012-3403,
CVE-2012-3481 and CVE-2012-5576
.

For the stable distribution (wheezy), these problems have been fixed in
version 2.8.2-2+deb7u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your gimp packages." );
	script_tag( name: "summary", value: "Murray McAllister discovered multiple integer and buffer overflows in the
XWD plugin in Gimp, which can result in the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gimp", ver: "2.6.10-1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gimp-data", ver: "2.6.10-1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gimp-dbg", ver: "2.6.10-1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgimp2.0", ver: "2.6.10-1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgimp2.0-dev", ver: "2.6.10-1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgimp2.0-doc", ver: "2.6.10-1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gimp", ver: "2.8.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gimp-data", ver: "2.8.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gimp-dbg", ver: "2.8.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgimp2.0", ver: "2.8.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgimp2.0-dev", ver: "2.8.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgimp2.0-doc", ver: "2.8.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

