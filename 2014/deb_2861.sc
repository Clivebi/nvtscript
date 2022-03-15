if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702861" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-1943" );
	script_name( "Debian Security Advisory DSA 2861-1 (file - denial of service)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-16 00:00:00 +0100 (Sun, 16 Feb 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2861.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "file on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 5.04-5+squeeze3.

For the stable distribution (wheezy), this problem has been fixed in
version 5.11-2+deb7u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your file packages." );
	script_tag( name: "summary", value: "It was discovered that file, a file type classification tool, contains a
flaw in the handling of indirect magic rules in the libmagic library,
which leads to an infinite recursion when trying to determine the file
type of certain files. The Common Vulnerabilities and Exposures project
ID CVE-2014-1943
has been assigned to identify this flaw. Additionally,
other well-crafted files might result in long computation times (while
using 100% CPU) and overlong results." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "file", ver: "5.04-5+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagic-dev", ver: "5.04-5+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagic1", ver: "5.04-5+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-magic", ver: "5.04-5+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-magic-dbg", ver: "5.04-5+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "file", ver: "5.11-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagic-dev", ver: "5.11-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagic1", ver: "5.11-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-magic", ver: "5.11-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-magic-dbg", ver: "5.11-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

