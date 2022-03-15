if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702888" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-4389", "CVE-2013-4491", "CVE-2013-6414", "CVE-2013-6415", "CVE-2013-6417" );
	script_name( "Debian Security Advisory DSA 2888-1 (ruby-actionpack-3.2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-27 00:00:00 +0100 (Thu, 27 Mar 2014)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2888.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ruby-actionpack-3.2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 3.2.6-6+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 3.2.16-3+0 of the rails-3.2 source package.

We recommend that you upgrade your ruby-actionpack-3.2 packages." );
	script_tag( name: "summary", value: "Toby Hsieh, Peter McLarnan, Ankit Gupta, Sudhir Rao and Kevin Reintjes
discovered multiple cross-site scripting and denial of service
vulnerabilities in Ruby Actionpack." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ruby-actionpack-3.2", ver: "3.2.6-6+deb7u1", rls: "DEB7" ) ) != NULL){
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

