if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703378" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-7673", "CVE-2015-7674" );
	script_name( "Debian Security Advisory DSA 3378-1 (gdk-pixbuf - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-24 00:00:00 +0200 (Sat, 24 Oct 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3378.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "gdk-pixbuf on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 2.26.1-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed in
version 2.31.1-2+deb8u3.

For the testing distribution (stretch), these problems have been fixed
in version 2.32.1-1 or earlier.

For the unstable distribution (sid), these problems have been fixed in
version 2.32.1-1 or earlier.

We recommend that you upgrade your gdk-pixbuf packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have
been discovered in gdk-pixbuf, a toolkit for image loading and pixel buffer
manipulation. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2015-7673
Gustavo Grieco discovered a heap overflow in the processing of TGA
images which may result in the execution of arbitrary code or denial
of service (process crash) if a malformed image is opened.

CVE-2015-7674
Gustavo Grieco discovered an integer overflow flaw in the processing
of GIF images which may result in the execution of arbitrary code or
denial of service (process crash) if a malformed image is opened." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gir1.2-gdkpixbuf-2.0", ver: "2.26.1-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0:i386", ver: "2.26.1-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0:amd64", ver: "2.26.1-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-common", ver: "2.26.1-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-dev", ver: "2.26.1-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-doc", ver: "2.26.1-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gir1.2-gdkpixbuf-2.0", ver: "2.31.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0:i386", ver: "2.31.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0:amd64", ver: "2.31.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0-dbg:i386", ver: "2.31.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0-dbg:amd64", ver: "2.31.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-common", ver: "2.31.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-dev", ver: "2.31.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-doc", ver: "2.31.1-2+deb8u3", rls: "DEB8" ) ) != NULL){
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

