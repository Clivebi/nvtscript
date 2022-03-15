if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702827" );
	script_version( "$Revision: 14276 $" );
	script_cve_id( "CVE-2013-2186" );
	script_name( "Debian Security Advisory DSA 2827-1 (libcommons-fileupload-java - arbitrary file upload via deserialization)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-24 00:00:00 +0100 (Tue, 24 Dec 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2827.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "libcommons-fileupload-java on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.2.2-1+deb6u1.

For the stable distribution (wheezy), this problem has been fixed in
version 1.2.2-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 1.3-2.1.

For the unstable distribution (sid), this problem has been fixed in
version 1.3-2.1.

We recommend that you upgrade your libcommons-fileupload-java packages." );
	script_tag( name: "summary", value: "It was discovered that Apache Commons FileUpload, a package to make it
easy to add robust, high-performance, file upload capability to servlets
and web applications, incorrectly handled file names with NULL bytes in
serialized instances. A remote attacker able to supply a serialized
instance of the DiskFileItem class, which will be deserialized on a
server, could use this flaw to write arbitrary content to any location
on the server that is accessible to the user running the application
server process." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libcommons-fileupload-java", ver: "1.2.2-1+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcommons-fileupload-java-doc", ver: "1.2.2-1+deb6u1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcommons-fileupload-java", ver: "1.2.2-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcommons-fileupload-java-doc", ver: "1.2.2-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

