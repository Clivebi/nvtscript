if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703644" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-5384" );
	script_name( "Debian Security Advisory DSA 3644-1 (fontconfig - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-08 00:00:00 +0200 (Mon, 08 Aug 2016)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3644.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "fontconfig on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this
problem has been fixed in version 2.11.0-6.3+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 2.11.0-6.5.

We recommend that you upgrade your fontconfig packages." );
	script_tag( name: "summary", value: "Tobias Stoeckmann discovered that cache
files are insufficiently validated in fontconfig, a generic font configuration library. An
attacker can trigger arbitrary free() calls, which in turn allows double
free attacks and therefore arbitrary code execution. In combination with
setuid binaries using crafted cache files, this could allow privilege
escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version
using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "fontconfig", ver: "2.11.0-6.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "fontconfig-config", ver: "2.11.0-6.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfontconfig1:amd64", ver: "2.11.0-6.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfontconfig1:i386", ver: "2.11.0-6.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfontconfig1-dbg", ver: "2.11.0-6.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfontconfig1-dev:amd64", ver: "2.11.0-6.3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libfontconfig1-dev:i386", ver: "2.11.0-6.3+deb8u1", rls: "DEB8" ) ) != NULL){
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

