if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704036" );
	script_version( "2021-09-14T09:01:51+0000" );
	script_cve_id( "CVE-2017-8808", "CVE-2017-8809", "CVE-2017-8810", "CVE-2017-8811", "CVE-2017-8812", "CVE-2017-8814", "CVE-2017-8815" );
	script_name( "Debian Security Advisory DSA 4036-1 (mediawiki - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 09:01:51 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-15 00:00:00 +0100 (Wed, 15 Nov 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-28 16:56:00 +0000 (Tue, 28 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4036.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "mediawiki on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1:1.27.4-1~deb9u1.

We recommend that you upgrade your mediawiki packages." );
	script_tag( name: "summary", value: "Multiple security vulnerabilities have been discovered in MediaWiki, a
website engine for collaborative work:

CVE-2017-8808
Cross-site-scripting with non-standard URL escaping and
$wgShowExceptionDetails disabled.

CVE-2017-8809
Reflected file download in API.

CVE-2017-8810
On private wikis the login form didn't distinguish between
login failure due to bad username and bad password.

CVE-2017-8811
It was possible to mangle HTML via raw message parameter
expansion.

CVE-2017-8812
id attributes in headlines allowed raw '>'.

CVE-2017-8814
Language converter could be tricked into replacing text inside tags.

CVE-2017-8815
Unsafe attribute injection via glossary rules in language converter." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mediawiki", ver: "1:1.27.4-1~deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mediawiki-classes", ver: "1:1.27.4-1~deb9u1", rls: "DEB9" ) ) != NULL){
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

