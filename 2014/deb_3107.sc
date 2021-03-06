if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703107" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-3580" );
	script_name( "Debian Security Advisory DSA 3107-1 (subversion - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-12-20 00:00:00 +0100 (Sat, 20 Dec 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3107.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "subversion on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.6.17dfsg-4+deb7u7.

For the unstable distribution (sid), this problem has been fixed in
version 1.8.10-5.

We recommend that you upgrade your subversion packages." );
	script_tag( name: "summary", value: "Evgeny Kotkov discovered a NULL pointer
dereference while processing REPORT requests in mod_dav_svn, the Subversion component
which is used to serve repositories with the Apache web server. A remote attacker
could abuse this vulnerability for a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.6.17dfsg-4+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-dev", ver: "1.6.17dfsg-4+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-doc", ver: "1.6.17dfsg-4+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-java", ver: "1.6.17dfsg-4+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-perl", ver: "1.6.17dfsg-4+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby", ver: "1.6.17dfsg-4+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby1.8", ver: "1.6.17dfsg-4+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn1", ver: "1.6.17dfsg-4+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-subversion", ver: "1.6.17dfsg-4+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion", ver: "1.6.17dfsg-4+deb7u7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion-tools", ver: "1.6.17dfsg-4+deb7u7", rls: "DEB7" ) ) != NULL){
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

