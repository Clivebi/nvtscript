if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702873" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-7345", "CVE-2014-2270" );
	script_name( "Debian Security Advisory DSA 2873-1 (file - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-11 00:00:00 +0100 (Tue, 11 Mar 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2873.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "file on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed
in version 5.04-5+squeeze4.

For the stable distribution (wheezy), these problems have been fixed in
version 5.11-2+deb7u2.

For the testing distribution (jessie), these problems have been fixed in
version 1:5.17-1.

For the unstable distribution (sid), these problems have been fixed in
version 1:5.17-1.

We recommend that you upgrade your file packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been found in file, a file type
classification tool.

Aaron Reffett reported a flaw in the way the file utility determined the
type of Portable Executable (PE) format files, the executable format
used on Windows. When processing a defective or intentionally prepared
PE executable which contains invalid offset information, the
file_strncmp routine will access memory that is out of bounds, causing
file to crash. The Common Vulnerabilities and Exposures project ID
CVE-2014-2270
has been assigned to identify this flaw.

Mike Frysinger reported that file's rule for detecting AWK scripts
significantly slows down file. The regular expression to detect AWK
files contained two star operators, which could be exploited to cause
excessive backtracking in the regex engine." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "file", ver: "5.04-5+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagic-dev", ver: "5.04-5+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagic1", ver: "5.04-5+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-magic", ver: "5.04-5+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-magic-dbg", ver: "5.04-5+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "file", ver: "5.11-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagic-dev", ver: "5.11-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagic1", ver: "5.11-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-magic", ver: "5.11-2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-magic-dbg", ver: "5.11-2+deb7u2", rls: "DEB7" ) ) != NULL){
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

