if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69954" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0446", "CVE-2011-0447" );
	script_name( "Debian Security Advisory DSA 2247-1 (rails)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202247-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in Rails, the Ruby web
application framework. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2011-0446

Multiple cross-site scripting (XSS) vulnerabilities when JavaScript
encoding is used, allow remote attackers to inject arbitrary web
script or HTML.

CVE-2011-0447

Rails does not properly validate HTTP requests that contain an
X-Requested-With header, which makes it easier for remote attackers
to conduct cross-site request forgery (CSRF) attacks.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.1.0-7+lenny0.1.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3.5-1.2+squeeze0.1.

For the unstable distribution (sid), this problem has been fixed in
version 2.3.11-0.1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your rails packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to rails
announced via advisory DSA 2247-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "rails", ver: "2.1.0-7+lenny0.2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionmailer-ruby", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionmailer-ruby1.8", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionpack-ruby", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionpack-ruby1.8", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby1.8", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby1.9.1", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiveresource-ruby", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiveresource-ruby1.8", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby1.8", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby1.9.1", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails-doc", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails-ruby1.8", ver: "2.3.5-1.2+squeeze0.1", rls: "DEB6" ) ) != NULL){
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

