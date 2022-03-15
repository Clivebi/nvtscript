if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702439" );
	script_version( "2020-11-12T08:48:24+0000" );
	script_cve_id( "CVE-2011-3045" );
	script_name( "Debian Security Advisory DSA 2439-1 (libpng - buffer overflow)" );
	script_tag( name: "last_modification", value: "2020-11-12 08:48:24 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2439.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "libpng on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 1.2.44-1+squeeze3. Packages for i386 are not yet available,
but will be provided shortly.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your libpng packages." );
	script_tag( name: "summary", value: "Glenn-Randers Pehrson discovered a buffer overflow in the libpng PNG
library, which could lead to the execution of arbitrary code if a
malformed image is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpng12-0", ver: "1.2.44-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpng12-0-udeb", ver: "1.2.44-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpng12-dev", ver: "1.2.44-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpng3", ver: "1.2.44-1+squeeze3", rls: "DEB6" ) ) != NULL){
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

