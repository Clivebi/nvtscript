if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68982" );
	script_version( "2020-11-12T10:09:08+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 10:09:08 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-2006" );
	script_name( "Debian Security Advisory DSA 2146-1 (mydms)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202146-1" );
	script_tag( name: "insight", value: "D. Fabian and L. Weichselbaum discovered a directory traversal
vulnerability in MyDMS, an open-source document management system based
on PHP and MySQL.

For the stable distribution (lenny), this problem has been fixed in
version 1.7.0-1+lenny1.

The testing distribution (squeeze) and the unstable distribution (sid)
no longer contain mydms packages." );
	script_tag( name: "solution", value: "We recommend that you upgrade your mydms packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to mydms
announced via advisory DSA 2146-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mydms", ver: "1.7.0-1+lenny1", rls: "DEB5" ) ) != NULL){
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

