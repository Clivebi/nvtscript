if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703022" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3613", "CVE-2014-3620" );
	script_name( "Debian Security Advisory DSA 3022-1 (curl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-09-10 00:00:00 +0200 (Wed, 10 Sep 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3022.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "curl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 7.26.0-1+wheezy10.

For the testing distribution (jessie), these problems have been fixed in
version 7.38.0-1.

For the unstable distribution (sid), these problems have been fixed in
version 7.38.0-1.

We recommend that you upgrade your curl packages." );
	script_tag( name: "summary", value: "Two vulnerabilities have been discovered in cURL, an URL transfer
library. They can be use to leak cookie information:

CVE-2014-3613
By not detecting and rejecting domain names for partial literal IP
addresses properly when parsing received HTTP cookies, libcurl can
be fooled to both sending cookies to wrong sites and into allowing
arbitrary sites to set cookies for others.

CVE-2014-3620
libcurl wrongly allows cookies to be set for Top Level Domains
(TLDs), thus making them apply broader than cookies are allowed.
This can allow arbitrary sites to set cookies that then would get
sent to a different and unrelated site or domain." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "curl", ver: "7.26.0-1+wheezy10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.26.0-1+wheezy10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.26.0-1+wheezy10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.26.0-1+wheezy10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.26.0-1+wheezy10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.26.0-1+wheezy10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.26.0-1+wheezy10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.26.0-1+wheezy10", rls: "DEB7" ) ) != NULL){
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

