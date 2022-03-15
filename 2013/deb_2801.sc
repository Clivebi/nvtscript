if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702801" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4407" );
	script_name( "Debian Security Advisory DSA 2801-1 (libhttp-body-perl - design error)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-11-21 00:00:00 +0100 (Thu, 21 Nov 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2801.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libhttp-body-perl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1.11-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 1.17-2.

For the unstable distribution (sid), this problem has been fixed in
version 1.17-2.

We recommend that you upgrade your libhttp-body-perl packages." );
	script_tag( name: "summary", value: "Jonathan Dolle reported a design error in HTTP::Body, a Perl module for
processing data from HTTP POST requests. The HTTP body multipart parser
creates temporary files which preserve the suffix of the uploaded file.
An attacker able to upload files to a service that uses
HTTP::Body::Multipart could potentially execute commands on the server
if these temporary filenames are used in subsequent commands without
further checks.

This update restricts the possible suffixes used for the created
temporary files.

The oldstable distribution (squeeze) is not affected by this problem." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libhttp-body-perl", ver: "1.11-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

