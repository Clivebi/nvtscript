if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703725" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2014-9911", "CVE-2015-2632", "CVE-2015-4844", "CVE-2016-0494", "CVE-2016-6293", "CVE-2016-7415" );
	script_name( "Debian Security Advisory DSA 3725-1 (icu - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-27 00:00:00 +0100 (Sun, 27 Nov 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3725.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "icu on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution
(jessie), these problems have been fixed in version 52.1-8+deb8u4.

For the unstable distribution (sid), these problems have been fixed in
version 57.1-5.

We recommend that you upgrade your icu packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were
discovered in the International Components for Unicode (ICU) library.

CVE-2014-9911
Michele Spagnuolo discovered a buffer overflow vulnerability which
might allow remote attackers to cause a denial of service or possibly
execute arbitrary code via crafted text.

CVE-2015-2632
An integer overflow vulnerability might lead into a denial of service
or disclosure of portion of application memory if an attacker has
control on the input file.

CVE-2015-4844
Buffer overflow vulnerabilities might allow an attacker with control
on the font file to perform a denial of service or,
possibly, execute arbitrary code.

CVE-2016-0494Integer signedness issues were introduced as part of the
CVE-2015-4844
fix.

CVE-2016-6293
A buffer overflow might allow an attacker to perform a denial of
service or disclosure of portion of application memory.

CVE-2016-7415
A stack-based buffer overflow might allow an attacker with control on
the locale string to perform a denial of service and, possibly,
execute arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icu-devtools", ver: "52.1-8+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icu-doc", ver: "52.1-8+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu-dev:amd64", ver: "52.1-8+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu-dev:i386", ver: "52.1-8+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu52:amd64", ver: "52.1-8+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu52:i386", ver: "52.1-8+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libicu52-dbg", ver: "52.1-8+deb8u4", rls: "DEB8" ) ) != NULL){
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

