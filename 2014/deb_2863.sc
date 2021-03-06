if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702863" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-4420" );
	script_name( "Debian Security Advisory DSA 2863-1 (libtar - directory traversal)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-18 00:00:00 +0100 (Tue, 18 Feb 2014)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2863.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "libtar on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.2.11-6+deb6u2.

For the stable distribution (wheezy), this problem has been fixed in
version 1.2.16-1+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 1.2.20-2.

We recommend that you upgrade your libtar packages." );
	script_tag( name: "summary", value: "A directory traversal attack was reported against libtar, a C library for
manipulating tar archives. The application does not validate the
filenames inside the tar archive, allowing to extract files in arbitrary
path. An attacker can craft a tar file to override files beyond the
tar_extract_glob and tar_extract_all prefix parameter." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libtar", ver: "1.2.11-6+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtar-dev", ver: "1.2.11-6+deb6u2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtar-dev", ver: "1.2.16-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtar0", ver: "1.2.16-1+deb7u2", rls: "DEB7" ) ) != NULL){
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

