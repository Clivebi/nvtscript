if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702942" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3941", "CVE-2014-3942", "CVE-2014-3943", "CVE-2014-3944", "CVE-2014-3945", "CVE-2014-3946" );
	script_name( "Debian Security Advisory DSA 2942-1 (typo3-src - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-01 00:00:00 +0200 (Sun, 01 Jun 2014)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2942.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "typo3-src on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 4.5.19+dfsg1-5+wheezy3.

For the testing distribution (jessie), this problem has been fixed in
version 4.5.34+dfsg1-1.

For the unstable distribution (sid), this problem has been fixed in
version 4.5.34+dfsg1-1.

We recommend that you upgrade your typo3-src packages." );
	script_tag( name: "summary", value: "Multiple security issues have been discovered in the Typo3 CMS." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "typo3", ver: "4.5.19+dfsg1-5+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-database", ver: "4.5.19+dfsg1-5+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-dummy", ver: "4.5.19+dfsg1-5+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-src-4.5", ver: "4.5.19+dfsg1-5+wheezy3", rls: "DEB7" ) ) != NULL){
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

