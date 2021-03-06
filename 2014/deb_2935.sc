if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702935" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3775" );
	script_name( "Debian Security Advisory DSA 2935-1 (libgadu - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-21 00:00:00 +0200 (Wed, 21 May 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2935.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libgadu on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1.11.2-1+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 1:1.12.0~rc3-1.

We recommend that you upgrade your libgadu packages." );
	script_tag( name: "summary", value: "It was discovered that malformed responses from a Gadu-Gadu file relay
server could lead to denial of service or the execution of arbitrary
code in applications linked to the libgadu library.

The oldstable distribution (squeeze) is not affected." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libgadu-dev", ver: "1.11.2-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgadu-doc", ver: "1.11.2-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgadu3", ver: "1.11.2-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgadu3-dbg", ver: "1.11.2-1+deb7u2", rls: "DEB7" ) ) != NULL){
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

