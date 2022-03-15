if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703157" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2014-4975", "CVE-2014-8080", "CVE-2014-8090" );
	script_name( "Debian Security Advisory DSA 3157-1 (ruby1.9.1 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-09 00:00:00 +0100 (Mon, 09 Feb 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3157.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ruby1.9.1 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 1.9.3.194-8.1+deb7u3.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 2.1.5-1 of the ruby2.1 source package.

For the unstable distribution (sid), these problems have been fixed in
version 2.1.5-1 of the ruby2.1 source package.

We recommend that you upgrade your ruby1.9.1 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were
discovered in the interpreter for the Ruby language:

CVE-2014-4975
The encodes() function in pack.c had an off-by-one error that could
lead to a stack-based buffer overflow. This could allow remote
attackers to cause a denial of service (crash) or arbitrary code
execution.

CVE-2014-8080,
CVE-2014-8090
The REXML parser could be coerced into allocating large string
objects that could consume all available memory on the system. This
could allow remote attackers to cause a denial of service (crash)." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libruby1.9.1", ver: "1.9.3.194-8.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libruby1.9.1-dbg", ver: "1.9.3.194-8.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtcltk-ruby1.9.1", ver: "1.9.3.194-8.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ri1.9.1", ver: "1.9.3.194-8.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1", ver: "1.9.3.194-8.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1-dev", ver: "1.9.3.194-8.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1-examples", ver: "1.9.3.194-8.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.1-full", ver: "1.9.3.194-8.1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby1.9.3", ver: "1.9.3.194-8.1+deb7u3", rls: "DEB7" ) ) != NULL){
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
