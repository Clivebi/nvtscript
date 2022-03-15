if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703719" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-9373", "CVE-2016-9374", "CVE-2016-9375", "CVE-2016-9376" );
	script_name( "Debian Security Advisory DSA 3719-1 (wireshark - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-21 00:00:00 +0100 (Mon, 21 Nov 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3719.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "wireshark on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 1.12.1+g01b65bf-4+deb8u10.

For the unstable distribution (sid), these problems have been fixed in
version 2.2.2+g9c5aae3-1.

We recommend that you upgrade your wireshark packages." );
	script_tag( name: "summary", value: "It was discovered that wireshark,
a network protocol analyzer, contained several vulnerabilities in the dissectors
for DCERPC, AllJoyn, DTN, and OpenFlow, that could lead to various crashes,
denial-of-service, or execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libwireshark-data", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark-dev", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark5:amd64", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark5:i386", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap-dev", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap4:amd64", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap4:i386", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil-dev", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil4:amd64", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil4:i386", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tshark", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-common", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dbg", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dev", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-doc", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-qt", ver: "1.12.1+g01b65bf-4+deb8u10", rls: "DEB8" ) ) != NULL){
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

