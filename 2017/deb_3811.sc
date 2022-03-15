if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703811" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_cve_id( "CVE-2017-5596", "CVE-2017-5597", "CVE-2017-6014", "CVE-2017-6467", "CVE-2017-6468", "CVE-2017-6469", "CVE-2017-6470", "CVE-2017-6471", "CVE-2017-6472", "CVE-2017-6473", "CVE-2017-6474" );
	script_name( "Debian Security Advisory DSA 3811-1 (wireshark - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-18 00:00:00 +0100 (Sat, 18 Mar 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3811.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "wireshark on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 1.12.1+g01b65bf-4+deb8u11.

For the unstable distribution (sid), these problems have been fixed in
version 2.2.5+g440fd4d-2.

We recommend that you upgrade your wireshark packages." );
	script_tag( name: "summary", value: "It was discovered that wireshark, a network protocol analyzer, contained
several vulnerabilities in the dissectors for ASTERIX, DHCPv6,
NetScaler, LDSS, IAX2, WSP, K12 and STANAG 4607, that could lead to
various crashes, denial-of-service or execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libwireshark-data", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark-dev", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark5", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap-dev", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap4", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil-dev", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil4", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tshark", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-common", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dbg", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dev", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-doc", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-qt", ver: "1.12.1+g01b65bf-4+deb8u11", rls: "DEB8" ) ) != NULL){
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

