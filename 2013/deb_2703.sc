if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702703" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1968", "CVE-2013-2112" );
	script_name( "Debian Security Advisory DSA 2703-1 (subversion - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-06-09 00:00:00 +0200 (Sun, 09 Jun 2013)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2703.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "subversion on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 1.6.12dfsg-7.

For the stable distribution (wheezy), these problems have been fixed in
version 1.6.17dfsg-4+deb7u3.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your subversion packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in Subversion, a version control
system. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2013-1968
Subversion repositories with the FSFS repository data store format
can be corrupted by newline characters in filenames. A remote
attacker with a malicious client could use this flaw to disrupt the
service for other users using that repository.

CVE-2013-2112
Subversion's svnserve server process may exit when an incoming TCP
connection is closed early in the connection process. A remote
attacker can cause svnserve to exit and thus deny service to users
of the server." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.6.12dfsg-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-dev", ver: "1.6.12dfsg-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-doc", ver: "1.6.12dfsg-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-java", ver: "1.6.12dfsg-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-perl", ver: "1.6.12dfsg-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby", ver: "1.6.12dfsg-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby1.8", ver: "1.6.12dfsg-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn1", ver: "1.6.12dfsg-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-subversion", ver: "1.6.12dfsg-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion", ver: "1.6.12dfsg-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion-tools", ver: "1.6.12dfsg-7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-svn", ver: "1.6.17dfsg-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-dev", ver: "1.6.17dfsg-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-doc", ver: "1.6.17dfsg-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-java", ver: "1.6.17dfsg-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-perl", ver: "1.6.17dfsg-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby", ver: "1.6.17dfsg-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn-ruby1.8", ver: "1.6.17dfsg-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libsvn1", ver: "1.6.17dfsg-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-subversion", ver: "1.6.17dfsg-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion", ver: "1.6.17dfsg-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "subversion-tools", ver: "1.6.17dfsg-4+deb7u3", rls: "DEB7" ) ) != NULL){
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

