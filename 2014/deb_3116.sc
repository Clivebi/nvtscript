if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703116" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-8628" );
	script_name( "Debian Security Advisory DSA 3116-1 (polarssl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-12-30 00:00:00 +0100 (Tue, 30 Dec 2014)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3116.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "polarssl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.2.9-1~deb7u4.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 1.3.9-1.

For the unstable distribution (sid), this problem has been fixed in
version 1.3.9-1.

We recommend that you upgrade your polarssl packages." );
	script_tag( name: "summary", value: "It was discovered that a memory leak
in parsing X.509 certificates may result in denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpolarssl-dev", ver: "1.2.9-1~deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolarssl-runtime", ver: "1.2.9-1~deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolarssl0", ver: "1.2.9-1~deb7u4", rls: "DEB7" ) ) != NULL){
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

