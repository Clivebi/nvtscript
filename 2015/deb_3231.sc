if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703231" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-0248", "CVE-2015-0251" );
	script_name( "Debian Security Advisory DSA 3231-1 (subversion - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-21 00:00:00 +0200 (Tue, 21 Apr 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3231.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "subversion on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 1.6.17dfsg-4+deb7u9.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 1.8.10-6.

For the unstable distribution (sid), these problems have been fixed in
version 1.8.10-6.

We recommend that you upgrade your subversion packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in Subversion, a version control system. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2015-0248
Subversion mod_dav_svn and svnserve were vulnerable to a remotely
triggerable assertion DoS vulnerability for certain requests with
dynamically evaluated revision numbers.

CVE-2015-0251
Subversion HTTP servers allow spoofing svn:author property values
for new revisions via specially crafted v1 HTTP protocol request
sequences." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-dev", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-doc", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-java", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-perl", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby1.8:amd64", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby1.8:i386", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn1:amd64", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn1:i386", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-subversion", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion-tools", ver: "1.6.17dfsg-4+deb7u9", rls: "DEB7" ) ) != NULL){
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

