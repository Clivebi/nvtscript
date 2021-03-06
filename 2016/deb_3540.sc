if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703540" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-2347" );
	script_name( "Debian Security Advisory DSA 3540-1 (lhasa - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-03 00:00:00 +0200 (Sun, 03 Apr 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3540.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|9|8)" );
	script_tag( name: "affected", value: "lhasa on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 0.0.7-2+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 0.2.0+git3fe46-1+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 0.3.1-1.

For the unstable distribution (sid), this problem has been fixed in
version 0.3.1-1.

We recommend that you upgrade your lhasa packages." );
	script_tag( name: "summary", value: "Marcin Noga discovered an integer
underflow in Lhasa, a lzh archive decompressor, which might result in the execution
of arbitrary code if a malformed archive is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "lhasa", ver: "0.0.7-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblhasa-dev", ver: "0.0.7-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblhasa0:amd64", ver: "0.0.7-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblhasa0:i386", ver: "0.0.7-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lhasa", ver: "0.3.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblhasa-dev", ver: "0.3.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblhasa0:amd64", ver: "0.3.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblhasa0:i386", ver: "0.3.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lhasa", ver: "0.2.0+git3fe46-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblhasa-dev", ver: "0.2.0+git3fe46-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblhasa0:amd64", ver: "0.2.0+git3fe46-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblhasa0:i386", ver: "0.2.0+git3fe46-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

