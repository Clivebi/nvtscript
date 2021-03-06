if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703243" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-3451" );
	script_name( "Debian Security Advisory DSA 3243-1 (libxml-libxml-perl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-05-01 00:00:00 +0200 (Fri, 01 May 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3243.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "libxml-libxml-perl on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 2.0001+dfsg-1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 2.0116+dfsg-1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 2.0116+dfsg-2.

We recommend that you upgrade your libxml-libxml-perl packages." );
	script_tag( name: "summary", value: "Tilmann Haak from xing.com discovered that XML::LibXML, a Perl interface
to the libxml2 library, did not respect the expand_entities parameter to
disable processing of external entities in some circumstances. This may
allow attackers to gain read access to otherwise protected resources,
depending on how the library is used." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxml-libxml-perl", ver: "2.0001+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-libxml-perl", ver: "2.0116+dfsg-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

