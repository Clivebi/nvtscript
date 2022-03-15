if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702814" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4484" );
	script_name( "Debian Security Advisory DSA 2814-1 (varnish - denial of service)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-12-09 00:00:00 +0100 (Mon, 09 Dec 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2814.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "varnish on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 2.1.3-8+deb6u1.

For the stable distribution (wheezy), this problem has been fixed in
version 3.0.2-2+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 3.0.5-1.

We recommend that you upgrade your varnish packages." );
	script_tag( name: "summary", value: "A denial of service vulnerability was reported in varnish, a state of
the art, high-performance web accelerator. With some configurations of
varnish a remote attacker could mount a denial of service (child-process
crash and temporary caching outage) via a GET request with trailing
whitespace characters and no URI." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libvarnish-dev", ver: "2.1.3-8+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvarnish1", ver: "2.1.3-8+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "varnish", ver: "2.1.3-8+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvarnishapi-dev", ver: "3.0.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvarnishapi1", ver: "3.0.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "varnish", ver: "3.0.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "varnish-dbg", ver: "3.0.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "varnish-doc", ver: "3.0.2-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

