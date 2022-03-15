if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703334" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-6251" );
	script_name( "Debian Security Advisory DSA 3334-1 (gnutls28 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-12 00:00:00 +0200 (Wed, 12 Aug 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3334.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "gnutls28 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 3.3.8-6+deb8u2.

For the unstable distribution (sid), this problem has been fixed in
version 3.3.17-1.

We recommend that you upgrade your gnutls28 packages." );
	script_tag( name: "summary", value: "Kurt Roeckx discovered that decoding a specific certificate with very
long DistinguishedName (DN) entries leads to double free. A remote
attacker can take advantage of this flaw by creating a specially crafted
certificate that, when processed by an application compiled against
GnuTLS, could cause the application to crash resulting in a denial of
service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gnutls-bin", ver: "3.3.8-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnutls-doc", ver: "3.3.8-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "guile-gnutls", ver: "3.3.8-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgnutls-deb0-28", ver: "3.3.8-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgnutls-openssl27", ver: "3.3.8-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgnutls28-dbg", ver: "3.3.8-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgnutls28-dev", ver: "3.3.8-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgnutlsxx28", ver: "3.3.8-6+deb8u2", rls: "DEB8" ) ) != NULL){
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

