if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703048" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-7206" );
	script_name( "Debian Security Advisory DSA 3048-1 (apt - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-10-08 00:00:00 +0200 (Wed, 08 Oct 2014)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3048.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "apt on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 0.9.7.9+deb7u6.

For the unstable distribution (sid), this problem has been fixed in
version 1.0.9.2.

We recommend that you upgrade your apt packages." );
	script_tag( name: "summary", value: "Guillem Jover discovered that the changelog retrieval functionality in
apt-get used temporary files in an insecure way, allowing a local user
to cause arbitrary files to be overwritten.

This vulnerability is neutralized by the fs.protected_symlinks setting in
the Linux kernel, which is enabled by default in Debian 7 Wheezy and up." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "apt", ver: "0.9.7.9+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-doc", ver: "0.9.7.9+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-transport-https", ver: "0.9.7.9+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-utils", ver: "0.9.7.9+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-inst1.5", ver: "0.9.7.9+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg-dev", ver: "0.9.7.9+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg-doc", ver: "0.9.7.9+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg4.12", ver: "0.9.7.9+deb7u6", rls: "DEB7" ) ) != NULL){
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

