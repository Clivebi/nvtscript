if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702931" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0198" );
	script_name( "Debian Security Advisory DSA 2931-1 (openssl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-18 00:00:00 +0200 (Sun, 18 May 2014)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2931.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "openssl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1.0.1e-2+deb7u9.

For the testing distribution (jessie), this problem has been fixed in
version 1.0.1g-4.

For the unstable distribution (sid), this problem has been fixed in
version 1.0.1g-4.

We recommend that you upgrade your openssl packages." );
	script_tag( name: "summary", value: "It was discovered that incorrect memory handling in OpenSSL's
do_ssl3_write() function could result in denial of service.

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
if(( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.0.1e-2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.0.1e-2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1e-2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssl1.0.0-dbg", ver: "1.0.1e-2+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssl", ver: "1.0.1e-2+deb7u9", rls: "DEB7" ) ) != NULL){
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

