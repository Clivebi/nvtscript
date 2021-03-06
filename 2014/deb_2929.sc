if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702929" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0081", "CVE-2014-0082", "CVE-2014-0130" );
	script_name( "Debian Security Advisory DSA 2929-1 (ruby-actionpack-3.2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-16 00:00:00 +0200 (Fri, 16 May 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2929.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ruby-actionpack-3.2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 3.2.6-6+deb7u2.

We recommend that you upgrade your ruby-actionpack-3.2 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in Action Pack, a component
of Ruby on Rails.

CVE-2014-0081
actionview/lib/action_view/helpers/number_helper.rb contains
multiple cross-site scripting vulnerabilities

CVE-2014-0082
actionpack/lib/action_view/template/text.rb performs symbol
interning on MIME type strings, allowing remote denial-of-service
attacks via increased memory consumption.

CVE-2014-0130
A directory traversal vulnerability in
actionpack/lib/abstract_controller/base.rb allows remote attackers
to read arbitrary files." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ruby-actionpack-3.2", ver: "3.2.6-6+deb7u2", rls: "DEB7" ) ) != NULL){
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

