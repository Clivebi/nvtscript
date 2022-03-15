if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703113" );
	script_version( "2020-02-10T07:58:04+0000" );
	script_cve_id( "CVE-2014-8139", "CVE-2014-8140", "CVE-2014-8141" );
	script_name( "Debian Security Advisory DSA 3113-1 (unzip - security update)" );
	script_tag( name: "last_modification", value: "2020-02-10 07:58:04 +0000 (Mon, 10 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-12-28 00:00:00 +0100 (Sun, 28 Dec 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3113.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "unzip on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 6.0-8+deb7u1.

For the upcoming stable distribution (jessie), these problems will be
fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 6.0-13.

We recommend that you upgrade your unzip packages." );
	script_tag( name: "summary", value: "Michele Spagnuolo of the Google
Security Team discovered that unzip, an extraction utility for archives
compressed in .zip format, is affected by heap-based buffer overflows within
the CRC32 verification function (CVE-2014-8139), the test_compr_eb() function
(CVE-2014-8140) and the getZip64Data() function (CVE-2014-8141), which may lead
to the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "unzip", ver: "6.0-8+deb7u1", rls: "DEB7" ) ) != NULL){
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

