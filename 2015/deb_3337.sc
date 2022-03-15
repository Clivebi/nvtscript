if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703337" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-4491" );
	script_name( "Debian Security Advisory DSA 3337-1 (gdk-pixbuf - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-18 00:00:00 +0200 (Tue, 18 Aug 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3337.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "gdk-pixbuf on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 2.26.1-1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 2.31.1-2+deb8u2.

For the testing distribution (stretch), this problem has been fixed
in version 2.31.5-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.31.5-1.

We recommend that you upgrade your gdk-pixbuf packages." );
	script_tag( name: "summary", value: "Gustavo Grieco discovered a
heap overflow in the processing of BMP images which may result in the
execution of arbitrary code if a malformed image is opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gir1.2-gdkpixbuf-2.0", ver: "2.26.1-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0:amd64", ver: "2.26.1-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0:i386", ver: "2.26.1-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-common", ver: "2.26.1-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-dev", ver: "2.26.1-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-doc", ver: "2.26.1-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

