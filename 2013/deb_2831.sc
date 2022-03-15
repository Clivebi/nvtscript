if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702831" );
	script_version( "$Revision: 14276 $" );
	script_cve_id( "CVE-2013-4969" );
	script_name( "Debian Security Advisory DSA 2831-1 (puppet - insecure temporary files)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-31 00:00:00 +0100 (Tue, 31 Dec 2013)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2831.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "puppet on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 2.6.2-5+squeeze9.

For the stable distribution (wheezy), this problem has been fixed in
version 2.7.23-1~deb7u2.

For the testing distribution (jessie), this problem has been fixed in
version 3.4.0-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.4.0-1.

We recommend that you upgrade your puppet packages." );
	script_tag( name: "summary", value: "An unsafe use of temporary files was discovered in Puppet, a tool for
centralized configuration management. An attacker can exploit this
vulnerability and overwrite an arbitrary file in the system." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "puppet", ver: "2.6.2-5+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-common", ver: "2.6.2-5+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-el", ver: "2.6.2-5+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-testsuite", ver: "2.6.2-5+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster", ver: "2.6.2-5+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-puppet", ver: "2.6.2-5+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet", ver: "2.7.23-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-common", ver: "2.7.23-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-el", ver: "2.7.23-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppet-testsuite", ver: "2.7.23-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster", ver: "2.7.23-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster-common", ver: "2.7.23-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "puppetmaster-passenger", ver: "2.7.23-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "vim-puppet", ver: "2.7.23-1~deb7u2", rls: "DEB7" ) ) != NULL){
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

