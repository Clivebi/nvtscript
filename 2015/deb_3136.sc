if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703136" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-1182" );
	script_name( "Debian Security Advisory DSA 3136-1 (polarssl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-01-24 00:00:00 +0100 (Sat, 24 Jan 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3136.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "polarssl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.2.9-1~deb7u5.

For the upcoming stable distribution (jessie) and the unstable
distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your polarssl packages." );
	script_tag( name: "summary", value: "A vulnerability was discovered in
PolarSSL, a lightweight crypto and SSL/TLS library. A remote attacker could
exploit this flaw using specially crafted certificates to mount a denial of
service against an application linked against the library (application crash), or
potentially, to execute arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpolarssl-dev", ver: "1.2.9-1~deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolarssl-runtime", ver: "1.2.9-1~deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolarssl0", ver: "1.2.9-1~deb7u5", rls: "DEB7" ) ) != NULL){
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

