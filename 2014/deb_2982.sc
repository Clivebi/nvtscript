if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702982" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3482", "CVE-2014-3483" );
	script_name( "Debian Security Advisory DSA 2982-1 (ruby-activerecord-3.2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-19 00:00:00 +0200 (Sat, 19 Jul 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2982.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ruby-activerecord-3.2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 3.2.6-5+deb7u1. Debian provides two variants of Ruby on Rails

in Wheezy (2.3 and 3.2). Support for the 2.3 variants had to be ceased
at this point. This affects the following source packages:
ruby-actionmailer-2.3, ruby-actionpack-2.3, ruby-activerecord-2.3,
ruby-activeresource-2.3, ruby-activesupport-2.3 and ruby-rails-2.3. The
version of Redmine in Wheezy still requires 2.3, you can use an updated
version from backports.debian.org which is compatible with rails 3.2.

For the unstable distribution (sid), these problems have been fixed in
version 3.2.19-1 of the rails-3.2 source package.

We recommend that you upgrade your ruby-activerecord-3.2 packages." );
	script_tag( name: "summary", value: "Sean Griffin discovered two vulnerabilities in the PostgreSQL adapter
for Active Record which could lead to SQL injection." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ruby-activerecord-3.2", ver: "3.2.6-5+deb7u1", rls: "DEB7" ) ) != NULL){
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

