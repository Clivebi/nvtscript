if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703368" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2013-4122" );
	script_name( "Debian Security Advisory DSA 3368-1 (cyrus-sasl2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-09-25 00:00:00 +0200 (Fri, 25 Sep 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3368.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "cyrus-sasl2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 2.1.26.dfsg1-13+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 2.1.26.dfsg1-14.

We recommend that you upgrade your cyrus-sasl2 packages." );
	script_tag( name: "summary", value: "It was discovered that cyrus-sasl2, a library implementing the Simple
Authentication and Security Layer, does not properly handle certain
invalid password salts. A remote attacker can take advantage of this
flaw to cause a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cyrus-sasl2-dbg", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-sasl2-doc", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-sasl2-heimdal-dbg", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cyrus-sasl2-mit-dbg", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsasl2-2", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsasl2-dev", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsasl2-modules", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsasl2-modules-db", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsasl2-modules-gssapi-heimdal", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsasl2-modules-gssapi-mit", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsasl2-modules-ldap", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsasl2-modules-otp", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsasl2-modules-sql", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sasl2-bin", ver: "2.1.26.dfsg1-13+deb8u1", rls: "DEB8" ) ) != NULL){
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

