if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702957" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3966" );
	script_name( "Debian Security Advisory DSA 2957-1 (mediawiki - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-12 00:00:00 +0200 (Thu, 12 Jun 2014)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2957.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "mediawiki on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1:1.19.16+dfsg-0+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 1:1.19.16+dfsg-1.

We recommend that you upgrade your mediawiki packages." );
	script_tag( name: "summary", value: "Omer Iqbal discovered that Mediawiki, a wiki engine, parses invalid
usernames on Special:PasswordReset as wikitext when $wgRawHtml is
enabled. On such wikis this allows an unauthenticated attacker to
insert malicious JavaScript, a cross site scripting attack." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mediawiki", ver: "1:1.19.16+dfsg-0+deb7u1", rls: "DEB7" ) ) != NULL){
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

