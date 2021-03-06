if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703538" );
	script_version( "2019-05-24T11:20:30+0000" );
	script_cve_id( "CVE-2015-8789", "CVE-2015-8790", "CVE-2015-8791" );
	script_name( "Debian Security Advisory DSA 3538-1 (libebml - security update)" );
	script_tag( name: "last_modification", value: "2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)" );
	script_tag( name: "creation_date", value: "2016-03-31 00:00:00 +0200 (Thu, 31 Mar 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3538.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8|7)" );
	script_tag( name: "affected", value: "libebml on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1.2.2-2+deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 1.3.0-2+deb8u1.

For the testing (stretch) and unstable (sid) distributions, these
problems have been fixed in version 1.3.3-1.

We recommend that you upgrade your libebml packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were
discovered in libebml, a library for manipulating Extensible Binary Meta
Language files.

CVE-2015-8789
Context-dependent attackers could trigger a use-after-free
vulnerability by providing a maliciously crafted EBML document.

CVE-2015-8790
Context-dependent attackers could obtain sensitive information
from the process's heap memory by using a maliciously crafted UTF-8
string.

CVE-2015-8791
Context-dependent attackers could obtain sensitive information
from the process's heap memory by using a maliciously crafted
length value in an EBML id." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libebml-dev:amd64", ver: "1.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libebml-dev:i386", ver: "1.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libebml4v5", ver: "1.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libebml-dev:amd64", ver: "1.3.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libebml-dev:i386", ver: "1.3.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libebml4:amd64", ver: "1.3.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libebml4:i386", ver: "1.3.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libebml-dev:amd64", ver: "1.2.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libebml-dev:i386", ver: "1.2.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libebml3:amd64", ver: "1.2.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libebml3:i386", ver: "1.2.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

