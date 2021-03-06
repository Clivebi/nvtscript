if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703671" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2016-7176", "CVE-2016-7177", "CVE-2016-7178", "CVE-2016-7179", "CVE-2016-7180" );
	script_name( "Debian Security Advisory DSA 3671-1 (wireshark - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-09-20 00:00:00 +0200 (Tue, 20 Sep 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3671.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "wireshark on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 1.12.1+g01b65bf-4+deb8u9.

For the testing distribution (stretch), these problems have been fixed
in version 2.2.0+g5368c50-1.

For the unstable distribution (sid), these problems have been fixed in
version 2.2.0+g5368c50-1.

We recommend that you upgrade your wireshark packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were
discovered in the dissectors for H.225, Catapult DCT2000, UMTS FP and IPMI,
which could result in denial of service or the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libwireshark-data", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark-dev", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark5:i386", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark5:amd64", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap-dev", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap4:amd64", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap4:i386", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil-dev", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil4:amd64", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil4:i386", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tshark", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-common", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dbg", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dev", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-doc", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-qt", ver: "1.12.1+g01b65bf-4+deb8u9", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark-data", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark-dev", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark8:amd64", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwireshark8:i386", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap-dev", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap6:i386", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwiretap6:amd64", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwscodecs1", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil-dev", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil7:amd64", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libwsutil7:i386", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "tshark", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-common", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dev", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-doc", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-gtk", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-qt", ver: "2.2.0+g5368c50-1", rls: "DEB9" ) ) != NULL){
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

