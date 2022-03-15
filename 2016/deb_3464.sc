if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703464" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2015-3226", "CVE-2015-3227", "CVE-2015-7576", "CVE-2015-7577", "CVE-2015-7581", "CVE-2016-0751", "CVE-2016-0752", "CVE-2016-0753" );
	script_name( "Debian Security Advisory DSA 3464-1 (rails - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-02-05 13:14:24 +0530 (Fri, 05 Feb 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3464.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "rails on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 2:4.1.8-1+deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 2:4.2.5.1-1.

We recommend that you upgrade your rails packages." );
	script_tag( name: "summary", value: "Multiple security issues have been
discovered in the Ruby on Rails web application development framework, which may
result in denial of service, cross-site scripting, information disclosure or
bypass of input validation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "rails", ver: "2:4.1.8-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-actionmailer", ver: "2:4.1.8-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-actionpack", ver: "2:4.1.8-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-actionview", ver: "2:4.1.8-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-activemodel", ver: "2:4.1.8-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-activerecord", ver: "2:4.1.8-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-activesupport", ver: "2:4.1.8-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-activesupport-2.3", ver: "2:4.1.8-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-rails", ver: "2:4.1.8-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-railties", ver: "2:4.1.8-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

