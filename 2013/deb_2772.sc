if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702772" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1464" );
	script_name( "Debian Security Advisory DSA 2772-1 (typo3-src - cross-site scripting)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-10-10 00:00:00 +0200 (Thu, 10 Oct 2013)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2772.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "typo3-src on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 4.5.19+dfsg1-5+wheezy1.

For the testing distribution (jessie), this problem has been fixed in
version 4.5.29+dfsg1-1.

For the unstable distribution (sid), this problem has been fixed in
version 4.5.29+dfsg1-1.

We recommend that you upgrade your typo3-src packages." );
	script_tag( name: "summary", value: "Markus Pieton and Vytautas Paulikas discovered that the embedded video
and audio player in the TYPO3 web content management system is suspectible
to cross-site-scripting." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "typo3", ver: "4.5.19+dfsg1-5+wheezy1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-database", ver: "4.5.19+dfsg1-5+wheezy1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-dummy", ver: "4.5.19+dfsg1-5+wheezy1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-src-4.5", ver: "4.5.19+dfsg1-5+wheezy1", rls: "DEB7" ) ) != NULL){
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

