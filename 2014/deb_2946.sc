if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702946" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-7323", "CVE-2014-1927", "CVE-2014-1928", "CVE-2014-1929" );
	script_name( "Debian Security Advisory DSA 2946-1 (python-gnupg - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-04 00:00:00 +0200 (Wed, 04 Jun 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2946.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "python-gnupg on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 0.3.6-1~deb7u1.

For the testing distribution (jessie), these problems have been fixed in
version 0.3.6-1.

For the unstable distribution (sid), these problems have been fixed in
version 0.3.6-1.

We recommend that you upgrade your python-gnupg packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered in the Python wrapper for the
Gnu Privacy Guard (GPG). Insufficient sanitising could lead to the
execution of arbitrary shell commands." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-gnupg", ver: "0.3.6-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-gnupg", ver: "0.3.6-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

