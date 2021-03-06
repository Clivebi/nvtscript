if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702824" );
	script_version( "$Revision: 14276 $" );
	script_cve_id( "CVE-2013-6422" );
	script_name( "Debian Security Advisory DSA 2824-1 (curl - unchecked tls/ssl certificate host name)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:43:56 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-19 00:00:00 +0100 (Thu, 19 Dec 2013)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2824.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "curl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 7.26.0-1+wheezy7.

For the unstable distribution (sid), this problem has been fixed in
version 7.34.0-1.

We recommend that you upgrade your curl packages." );
	script_tag( name: "summary", value: "Marc Deslauriers discovered that curl, a file retrieval tool, would
mistakenly skip verifying the CN and SAN name fields when digital
signature verification was disabled in the libcurl GnuTLS backend.

The default configuration for the curl package is not affected by this
issue since the digital signature verification is enabled by default.

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
if(( res = isdpkgvuln( pkg: "curl", ver: "7.26.0-1+wheezy7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.26.0-1+wheezy7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.26.0-1+wheezy7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.26.0-1+wheezy7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.26.0-1+wheezy7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.26.0-1+wheezy7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.26.0-1+wheezy7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.26.0-1+wheezy7", rls: "DEB7" ) ) != NULL){
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

