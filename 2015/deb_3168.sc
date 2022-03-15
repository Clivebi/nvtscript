if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703168" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2012-6684" );
	script_name( "Debian Security Advisory DSA 3168-1 (ruby-redcloth - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-22 00:00:00 +0100 (Sun, 22 Feb 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3168.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ruby-redcloth on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 4.2.9-2+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 4.2.9-4.

We recommend that you upgrade your ruby-redcloth packages." );
	script_tag( name: "summary", value: "Kousuke Ebihara discovered that redcloth,
a Ruby module used to convert Textile markup to HTML, did not properly sanitize its
input. This allowed a remote attacker to perform a cross-site
scripting attack by injecting arbitrary JavaScript code into the
generated HTML." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libredcloth-ruby", ver: "4.2.9-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libredcloth-ruby-doc", ver: "4.2.9-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libredcloth-ruby1.8", ver: "4.2.9-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libredcloth-ruby1.9.1", ver: "4.2.9-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-redcloth", ver: "4.2.9-2+deb7u2", rls: "DEB7" ) ) != NULL){
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

