if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703309" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-5522", "CVE-2015-5523" );
	script_name( "Debian Security Advisory DSA 3309-1 (tidy - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-07-18 00:00:00 +0200 (Sat, 18 Jul 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3309.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "tidy on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), these problems have been fixed
in version 20091223cvs-1.2+deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 20091223cvs-1.4+deb8u1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your tidy packages." );
	script_tag( name: "summary", value: "Fernando Muoz discovered that invalid HTML input passed to tidy, an
HTML syntax checker and reformatter, could trigger a buffer overflow.
This could allow remote attackers to cause a denial of service (crash)
or potentially execute arbitrary code.

Geoff McLane also discovered that a similar issue could trigger an
integer overflow, leading to a memory allocation of 4GB. This could
allow remote attackers to cause a denial of service by saturating the
target's memory." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libtidy-0.99-0", ver: "20091223cvs-1.2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtidy-dev", ver: "20091223cvs-1.2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tidy", ver: "20091223cvs-1.2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tidy-doc", ver: "20091223cvs-1.2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtidy-0.99-0", ver: "20091223cvs-1.4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtidy-dev", ver: "20091223cvs-1.4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tidy", ver: "20091223cvs-1.4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tidy-doc", ver: "20091223cvs-1.4+deb8u1", rls: "DEB8" ) ) != NULL){
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

