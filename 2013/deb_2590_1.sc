if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702590" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-4048", "CVE-2012-4296" );
	script_name( "Debian Security Advisory DSA 2590-1 (wireshark - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2590.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "wireshark on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), these problems have been fixed in
version 1.2.11-6+squeeze8.

For the unstable distribution (sid), these problems have been fixed in
version 1.8.2-1.

We recommend that you upgrade your wireshark packages." );
	script_tag( name: "summary", value: "Bjorn Mork and Laurent Butti discovered crashes in the PPP and RTPS2
dissectors, which could potentially result in the execution of arbitrary
code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "tshark", ver: "1.2.11-6+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark", ver: "1.2.11-6+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-common", ver: "1.2.11-6+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dbg", ver: "1.2.11-6+squeeze8", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wireshark-dev", ver: "1.2.11-6+squeeze8", rls: "DEB6" ) ) != NULL){
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

