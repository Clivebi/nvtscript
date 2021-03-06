if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702830" );
	script_version( "$Revision: 14276 $" );
	script_cve_id( "CVE-2013-4492" );
	script_name( "Debian Security Advisory DSA 2830-1 (ruby-i18n - cross-site scripting)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-30 00:00:00 +0100 (Mon, 30 Dec 2013)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2830.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ruby-i18n on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 0.6.0-3+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 0.6.9-1.

We recommend that you upgrade your ruby-i18n packages." );
	script_tag( name: "summary", value: "Peter McLarnan discovered that the internationalization component of
Ruby on Rails does not properly encode parameters in generated HTML
code, resulting in a cross-site scripting vulnerability. This update
corrects the underlying vulnerability in the i18n gem, as provided by
the ruby-i18n package.

The oldstable distribution (squeeze) is not affected by this problem.
The libi18n-ruby package does not contain the vulnerable code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libi18n-ruby", ver: "0.6.0-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libi18n-ruby1.8", ver: "0.6.0-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libi18n-ruby1.9.1", ver: "0.6.0-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ruby-i18n", ver: "0.6.0-3+deb7u1", rls: "DEB7" ) ) != NULL){
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

