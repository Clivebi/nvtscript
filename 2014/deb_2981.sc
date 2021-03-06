if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702981" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-4911" );
	script_name( "Debian Security Advisory DSA 2981-1 (polarssl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-18 00:00:00 +0200 (Fri, 18 Jul 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2981.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "polarssl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1.2.9-1~deb7u3.

For the testing distribution (jessie), this problem has been fixed in
version 1.3.7-2.1.

For the unstable distribution (sid), this problem has been fixed in
version 1.3.7-2.1.

We recommend that you upgrade your polarssl packages." );
	script_tag( name: "summary", value: "A flaw was discovered in PolarSSL, a lightweight crypto and SSL/TLS
library, which can be exploited by a remote unauthenticated attacker to
mount a denial of service against PolarSSL servers that offer GCM
ciphersuites. Potentially clients are affected too if a malicious server
decides to execute the denial of service attack against its clients." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpolarssl-dev", ver: "1.2.9-1~deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolarssl-runtime", ver: "1.2.9-1~deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolarssl0", ver: "1.2.9-1~deb7u3", rls: "DEB7" ) ) != NULL){
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

