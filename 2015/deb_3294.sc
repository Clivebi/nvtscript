if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703294" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-4651", "CVE-2015-4652" );
	script_name( "Debian Security Advisory DSA 3294-1 (wireshark - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-23 00:00:00 +0200 (Tue, 23 Jun 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3294.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "wireshark on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 1.12.1+g01b65bf-4+deb8u2.

For the testing distribution (stretch), these problems have been fixed
in version 1.12.6+gee1fce6-1.

For the unstable distribution (sid), these problems have been fixed in
version 1.12.6+gee1fce6-1.

We recommend that you upgrade your wireshark packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered in the dissectors for WCCP
and GSM DTAP, which could result in denial of service.

The oldstable distribution (wheezy) is not affected." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libwireshark-data", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark-dev", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark5", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap-dev", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap4", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil-dev", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil4", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tshark", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-common", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dbg", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dev", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-doc", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-qt", ver: "1.12.6+gee1fce6-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark-data", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark-dev", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark5", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap-dev", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap4", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil-dev", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil4", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tshark", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-common", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dbg", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dev", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-doc", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-qt", ver: "1.12.1+g01b65bf-4+deb8u2", rls: "DEB8" ) ) != NULL){
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

