if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71137" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-3026" );
	script_version( "2020-04-21T06:28:23+0000" );
	script_tag( name: "last_modification", value: "2020-04-21 06:28:23 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-03-12 11:30:59 -0400 (Mon, 12 Mar 2012)" );
	script_name( "Debian Security Advisory DSA 2410-1 (libpng)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202410-1" );
	script_tag( name: "insight", value: "Jueri Aedla discovered an integer overflow in the libpng PNG library,
which could lead to the execution of arbitrary code if a malformed
image is processed.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.44-1+squeeze2.

For the unstable distribution (sid), this problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libpng packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libpng
announced via advisory DSA 2410-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpng12-0", ver: "1.2.44-1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpng12-0-udeb", ver: "1.2.44-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpng12-dev", ver: "1.2.44-1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpng3", ver: "1.2.44-1+squeeze2", rls: "DEB6" ) ) != NULL){
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

