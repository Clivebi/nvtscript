if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702717" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-2154", "CVE-2013-2210" );
	script_name( "Debian Security Advisory DSA 2717-1 (xml-security-c - heap overflow)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-06-28 00:00:00 +0200 (Fri, 28 Jun 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2717.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "xml-security-c on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.5.1-3+squeeze3.

For the stable distribution (wheezy), this problem has been fixed in
version 1.6.1-5+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 1.6.1-7.

We recommend that you upgrade your xml-security-c packages." );
	script_tag( name: "summary", value: "Jon Erickson of iSIGHT Partners Labs discovered a heap overflow in
xml-security-c, an implementation of the XML Digital Security
specification. The fix to address
CVE-2013-2154

introduced the
possibility of a heap overflow in the processing of malformed XPointer
expressions in the XML Signature Reference processing code, possibly
leading to arbitrary code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxml-security-c-dev", ver: "1.5.1-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-security-c15", ver: "1.5.1-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-security-c-dev", ver: "1.6.1-5+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-security-c16", ver: "1.6.1-5+deb7u2", rls: "DEB7" ) ) != NULL){
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

