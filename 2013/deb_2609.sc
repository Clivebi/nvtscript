if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702609" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-0155" );
	script_name( "Debian Security Advisory DSA 2609-1 (rails - SQL query manipulation)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-01-16 00:00:00 +0100 (Wed, 16 Jan 2013)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2609.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "rails on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 2.3.5-1.2+squeeze5.

We recommend that you upgrade your rails packages." );
	script_tag( name: "summary", value: "An interpretation conflict can cause the Active Record component of
Rails, a web framework for the Ruby programming language, to truncate
queries in unexpected ways. This may allow attackers to elevate their
privileges." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libactionmailer-ruby", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionmailer-ruby1.8", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionpack-ruby", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactionpack-ruby1.8", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby1.8", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiverecord-ruby1.9.1", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiveresource-ruby", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactiveresource-ruby1.8", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby1.8", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libactivesupport-ruby1.9.1", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails-doc", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rails-ruby1.8", ver: "2.3.5-1.2+squeeze5", rls: "DEB6" ) ) != NULL){
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

