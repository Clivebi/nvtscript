if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702596" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-6453" );
	script_name( "Debian Security Advisory DSA 2596-1 (mediawiki-extensions - cross-site scripting)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2596.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "mediawiki-extensions on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 2.3squeeze2.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 2.11.

We recommend that you upgrade your mediawiki-extensions packages." );
	script_tag( name: "summary", value: "Thorsten Glaser discovered that the RSSReader extension for MediaWiki, a
website engine for collaborative work, does not properly escape tags in
feeds. This could allow a malicious feed to inject JavaScript into the
MediaWiki pages." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mediawiki-extensions", ver: "2.3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mediawiki-extensions-base", ver: "2.3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mediawiki-extensions-collection", ver: "2.3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mediawiki-extensions-confirmedit", ver: "2.3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mediawiki-extensions-fckeditor", ver: "2.3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mediawiki-extensions-geshi", ver: "2.3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mediawiki-extensions-graphviz", ver: "2.3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mediawiki-extensions-ldapauth", ver: "2.3squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mediawiki-extensions-openid", ver: "2.3squeeze2", rls: "DEB6" ) ) != NULL){
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

