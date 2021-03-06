if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703063" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-8483" );
	script_name( "Debian Security Advisory DSA 3063-1 (quassel - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-11-02 00:00:00 +0100 (Sun, 02 Nov 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3063.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "quassel on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 0.8.0-1+deb7u3.

For the unstable distribution (sid), this problem has been fixed in
version 0.10.0-2.1 (will be available soon).

We recommend that you upgrade your quassel packages." );
	script_tag( name: "summary", value: "An out-of-bounds read vulnerability was discovered in Quassel-core, one
of the components of the distributed IRC client Quassel. An attacker can
send a crafted message that crash to component causing a denial of
services or disclosure of information from process memory." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "quassel", ver: "0.8.0-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-client", ver: "0.8.0-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-client-kde4", ver: "0.8.0-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-core", ver: "0.8.0-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-data", ver: "0.8.0-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-data-kde4", ver: "0.8.0-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "quassel-kde4", ver: "0.8.0-1+deb7u3", rls: "DEB7" ) ) != NULL){
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

