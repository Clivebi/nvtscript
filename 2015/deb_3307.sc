if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703307" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-1868", "CVE-2015-5470" );
	script_name( "Debian Security Advisory DSA 3307-1 (pdns-recursor - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-09 00:00:00 +0200 (Thu, 09 Jul 2015)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3307.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "pdns-recursor on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 3.6.2-2+deb8u2.

For the testing distribution (stretch), this problem has been fixed
in version 3.7.3-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.7.3-1.

We recommend that you upgrade your pdns-recursor packages." );
	script_tag( name: "summary", value: "Toshifumi Sakaguchi discovered that the patch applied to pdns-recursor,
a recursive DNS server, fixing
CVE-2015-1868
, was insufficient in some
cases, allowing remote attackers to cause a denial of service
(service-affecting CPU spikes and in some cases a crash)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "pdns-recursor", ver: "3.7.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-recursor-dbg", ver: "3.7.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-recursor", ver: "3.6.2-2+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-recursor-dbg", ver: "3.6.2-2+deb8u2", rls: "DEB8" ) ) != NULL){
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

