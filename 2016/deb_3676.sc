if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703676" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-1243", "CVE-2016-1244" );
	script_name( "Debian Security Advisory DSA 3676-1 (unadf - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-09-24 00:00:00 +0200 (Sat, 24 Sep 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3676.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|7)" );
	script_tag( name: "affected", value: "unadf on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 0.7.11a-3+deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 0.7.11a-3+deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 0.7.11a-4.

We recommend that you upgrade your unadf packages." );
	script_tag( name: "summary", value: "Tuomas Rasanen discovered two vulnerabilities
in unADF, a tool to extract files from an Amiga Disk File dump (.adf):

CVE-2016-1243
A stack buffer overflow in the function extractTree() might allow an
attacker, with control on the content of a ADF file, to execute
arbitrary code with the privileges of the program execution.

CVE-2016-1244
The unADF extractor creates the path in the destination via a mkdir
in a system() call. Since there was no sanitization on the input of
the filenames, an attacker can directly inject code in the pathnames
of archived directories in an ADF file." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "unadf", ver: "0.7.11a-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "unadf", ver: "0.7.11a-3+deb7u1", rls: "DEB7" ) ) != NULL){
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

