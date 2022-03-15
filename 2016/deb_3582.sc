if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703582" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2015-1283", "CVE-2016-0718", "CVE-2016-4472" );
	script_name( "Debian Security Advisory DSA 3582-1 (expat - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-18 00:00:00 +0200 (Wed, 18 May 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3582.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "expat on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 2.1.0-6+deb8u2. Additionally this update
refreshes the fix for CVE-2015-1283 to avoid relying on undefined behavior.

We recommend that you upgrade your expat packages." );
	script_tag( name: "summary", value: "Gustavo Grieco discovered that Expat,
an XML parsing C library, does not properly handle certain kinds of malformed input
documents, resulting in buffer overflows during processing and error reporting. A
remote attacker can take advantage of this flaw to cause an application using
the Expat library to crash, or potentially, to execute arbitrary code
with the privileges of the user running the application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "expat", ver: "2.1.0-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib64expat1", ver: "2.1.0-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lib64expat1-dev", ver: "2.1.0-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1:amd64", ver: "2.1.0-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1:i386", ver: "2.1.0-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1-dev:amd64", ver: "2.1.0-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libexpat1-dev:i386", ver: "2.1.0-6+deb8u2", rls: "DEB8" ) ) != NULL){
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

