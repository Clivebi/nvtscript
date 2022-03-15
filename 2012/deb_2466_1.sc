if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71345" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-1099" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:44:05 -0400 (Thu, 31 May 2012)" );
	script_name( "Debian Security Advisory DSA 2466-1 (rails)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202466-1" );
	script_tag( name: "insight", value: "Sergey Nartimov discovered that in Rails, a Ruby based framework for
web development, when developers generate html options tags manually,
user input concatenated with manually built tags may not be escaped
and an attacker can inject arbitrary HTML into the document.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3.5-1.2+squeeze3.

For the testing distribution (wheezy) and unstable distribution (sid),
this problem has been fixed in version 2.3.14." );
	script_tag( name: "solution", value: "We recommend that you upgrade your rails packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to rails
announced via advisory DSA 2466-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libactionmailer-ruby", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionmailer-ruby1.8", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionpack-ruby", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionpack-ruby1.8", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby1.8", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby1.9.1", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiveresource-ruby", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiveresource-ruby1.8", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby1.8", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby1.9.1", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails-doc", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails-ruby1.8", ver: "2.3.5-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionmailer-ruby", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionmailer-ruby1.8", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionpack-ruby", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionpack-ruby1.8", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby1.8", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby1.9.1", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiveresource-ruby", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiveresource-ruby1.8", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby1.8", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby1.9.1", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails-doc", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails-ruby1.8", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-actionmailer", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-actionpack", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-activerecord", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-activeresource", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-activesupport", ver: "2.3.14.1", rls: "DEB7" ) ) != NULL){
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

