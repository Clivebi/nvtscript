if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703571" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-4561" );
	script_name( "Debian Security Advisory DSA 3571-1 (ikiwiki - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-08 00:00:00 +0200 (Sun, 08 May 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3571.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "ikiwiki on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 3.20141016.3.

For the unstable distribution (sid), this problem has been fixed in
version 3.20160506.

We recommend that you upgrade your ikiwiki packages." );
	script_tag( name: "summary", value: "Simon McVittie discovered a cross-site
scripting vulnerability in the error reporting of Ikiwiki, a wiki compiler. This
update also hardens ikiwiki's use of imagemagick in the img plugin." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ikiwiki", ver: "3.20141016.3", rls: "DEB8" ) ) != NULL){
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

