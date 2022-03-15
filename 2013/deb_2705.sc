if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702705" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-2132" );
	script_name( "Debian Security Advisory DSA 2705-1 (pymongo - denial of service)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-06-10 00:00:00 +0200 (Mon, 10 Jun 2013)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2705.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "pymongo on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 2.2-4+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 2.5.2-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.5.2-1.

We recommend that you upgrade your pymongo packages." );
	script_tag( name: "summary", value: "Jibbers McGee discovered that PyMongo, a high-performance schema-free
document-oriented data store, is prone to a denial-of-service
vulnerability.

An attacker can remotely trigger a NULL pointer dereference causing MongoDB
to crash.

The oldstable distribution (squeeze) is not affected by this issue." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-bson", ver: "2.2-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-bson-ext", ver: "2.2-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-gridfs", ver: "2.2-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pymongo", ver: "2.2-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pymongo-doc", ver: "2.2-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pymongo-ext", ver: "2.2-4+deb7u1", rls: "DEB7" ) ) != NULL){
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

