if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703065" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-2172" );
	script_name( "Debian Security Advisory DSA 3065-1 (libxml-security-java - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-11-06 00:00:00 +0100 (Thu, 06 Nov 2014)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3065.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libxml-security-java on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1.4.5-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 1.5.5-2.

For the unstable distribution (sid), this problem has been fixed in
version 1.5.5-2.

We recommend that you upgrade your libxml-security-java packages." );
	script_tag( name: "summary", value: "James Forshaw discovered that, in Apache Santuario XML Security for
Java, CanonicalizationMethod parameters were incorrectly validated:
by specifying an arbitrary weak canonicalization algorithm, an
attacker could spoof XML signatures." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxml-security-java", ver: "1.4.5-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-security-java-doc", ver: "1.4.5-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

