if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703194" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804" );
	script_name( "Debian Security Advisory DSA 3194-1 (libxfont - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-17 00:00:00 +0100 (Tue, 17 Mar 2015)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3194.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libxfont on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 1.4.5-5.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your libxfont packages." );
	script_tag( name: "summary", value: "Ilja van Sprundel, Alan
Coopersmith and William Robinet discovered multiple issues in libxfont's
code to process BDF fonts, which might result in privilege escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxfont-dev", ver: "1.4.5-5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1", ver: "1.4.5-5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1-dbg", ver: "1.4.5-5", rls: "DEB7" ) ) != NULL){
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

