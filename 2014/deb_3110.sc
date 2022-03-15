if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703110" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-9475" );
	script_name( "Debian Security Advisory DSA 3110-1 (mediawiki - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-12-23 00:00:00 +0100 (Tue, 23 Dec 2014)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3110.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "mediawiki on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.19.20+dfsg-0+deb7u3. This version
additionally fixes a regression introduced in the previous release, DSA-3100-1.

For the upcoming stable distribution (jessie) and unstable
distribution (sid), this problem has been fixed in version
1:1.19.20+dfsg-2.2.

We recommend that you upgrade your mediawiki packages." );
	script_tag( name: "summary", value: "A flaw was discovered in mediawiki, a
wiki engine: thumb.php outputs wikitext messages as raw HTML, potentially
leading to cross-site scripting (XSS)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mediawiki", ver: "1.19.20+dfsg-0+deb7u3", rls: "DEB7" ) ) != NULL){
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
