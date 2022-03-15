if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703386" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-7696", "CVE-2015-7697" );
	script_name( "Debian Security Advisory DSA 3386-1 (unzip - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-31 00:00:00 +0100 (Sat, 31 Oct 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3386.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|9|8)" );
	script_tag( name: "affected", value: "unzip on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 6.0-8+deb7u4.

For the stable distribution (jessie), these problems have been fixed in
version 6.0-16+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 6.0-19.

For the unstable distribution (sid), these problems have been fixed in
version 6.0-19.

We recommend that you upgrade your unzip packages." );
	script_tag( name: "summary", value: "Two vulnerabilities have been
found in unzip, a de-archiver for .zip files. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2015-7696
Gustavo Grieco discovered that unzip incorrectly handled certain
password protected archives. If a user or automated system were
tricked into processing a specially crafted zip archive, an attacker
could possibly execute arbitrary code.

CVE-2015-7697
Gustavo Grieco discovered that unzip incorrectly handled certain
malformed archives. If a user or automated system were tricked into
processing a specially crafted zip archive, an attacker could
possibly cause unzip to hang, resulting in a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "unzip", ver: "6.0-8+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "unzip", ver: "6.0-19", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "unzip", ver: "6.0-16+deb8u1", rls: "DEB8" ) ) != NULL){
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

