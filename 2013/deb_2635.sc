if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702635" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1049" );
	script_name( "Debian Security Advisory DSA 2635-1 (cfingerd - buffer overflow)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-03-01 00:00:00 +0100 (Fri, 01 Mar 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2635.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "cfingerd on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 1.4.3-3+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 1.4.3-3.1.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.3-3.1.

We recommend that you upgrade your cfingerd packages." );
	script_tag( name: "summary", value: "Malcolm Scott discovered a remote-exploitable buffer overflow in the
RFC1413 (ident) client of cfingerd, a configurable finger daemon. This
vulnerability was introduced in a previously applied patch to the
cfingerd package in 1.4.3-3." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cfingerd", ver: "1.4.3-3+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cfingerd", ver: "1.4.3-3.1", rls: "DEB7" ) ) != NULL){
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

