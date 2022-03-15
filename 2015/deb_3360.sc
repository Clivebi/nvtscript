if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703360" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-1270" );
	script_name( "Debian Security Advisory DSA 3360-1 (icu - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-09-15 00:00:00 +0200 (Tue, 15 Sep 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3360.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "icu on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 52.1-8+deb8u3.

For the testing distribution (stretch), this problem has been fixed
in version 55.1-5.

For the unstable distribution (sid), this problem has been fixed in
version 55.1-5.

We recommend that you upgrade your icu packages." );
	script_tag( name: "summary", value: "It was discovered that the International Components for Unicode (ICU)
library mishandles converter names starting with x-
, which allows
remote attackers to cause a denial of service (read of uninitialized
memory) or possibly have unspecified other impact via a crafted file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icu-devtools", ver: "52.1-8+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icu-doc", ver: "52.1-8+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu-dev", ver: "52.1-8+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu52", ver: "52.1-8+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu52-dbg", ver: "52.1-8+deb8u3", rls: "DEB8" ) ) != NULL){
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

