if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891634" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2017-11406", "CVE-2017-11407", "CVE-2017-11409", "CVE-2017-13765", "CVE-2017-15191", "CVE-2017-17935", "CVE-2017-17997", "CVE-2017-7700", "CVE-2017-7703", "CVE-2017-7746", "CVE-2017-7747", "CVE-2017-9766", "CVE-2018-11356", "CVE-2018-11357", "CVE-2018-11359", "CVE-2018-16057", "CVE-2018-16058", "CVE-2018-19622", "CVE-2018-19623", "CVE-2018-19624", "CVE-2018-19625", "CVE-2018-19626", "CVE-2018-7322", "CVE-2018-7323", "CVE-2018-7324", "CVE-2018-7325", "CVE-2018-7331", "CVE-2018-7336", "CVE-2018-7417", "CVE-2018-7418", "CVE-2018-7420", "CVE-2018-9256", "CVE-2018-9259", "CVE-2018-9260", "CVE-2018-9262", "CVE-2018-9263", "CVE-2018-9265", "CVE-2018-9267", "CVE-2018-9268", "CVE-2018-9269", "CVE-2018-9270" );
	script_name( "Debian LTS: Security Advisory for wireshark (DLA-1634-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-16 00:00:00 +0100 (Wed, 16 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/01/msg00010.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "wireshark on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.12.1+g01b65bf-4+deb8u16.

We recommend that you upgrade your wireshark packages." );
	script_tag( name: "summary", value: "Several issues in wireshark, a tool that captures and analyzes packets
off the wire, have been found by different people.
These are basically issues with length checks or invalid memory access in
different dissectors. This could result in infinite loops or crashes by
malicious packets." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libwireshark-data", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwireshark-dev", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwireshark5", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwiretap-dev", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwiretap4", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwsutil-dev", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwsutil4", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tshark", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark-common", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark-dbg", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark-dev", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark-doc", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wireshark-qt", ver: "1.12.1+g01b65bf-4+deb8u16", rls: "DEB8" ) )){
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

