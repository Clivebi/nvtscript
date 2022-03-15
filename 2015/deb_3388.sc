if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703388" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2014-9750", "CVE-2014-9751", "CVE-2015-3405", "CVE-2015-5146", "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7850", "CVE-2015-7852", "CVE-2015-7855", "CVE-2015-7871" );
	script_name( "Debian Security Advisory DSA 3388-1 (ntp - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-06 15:29:25 +0530 (Fri, 06 May 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3388.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9|7)" );
	script_tag( name: "affected", value: "ntp on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1:4.2.6.p5+dfsg-2+deb7u6.

For the stable distribution (jessie), these problems have been fixed in
version 1:4.2.6.p5+dfsg-7+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 1:4.2.8p4+dfsg-3.

For the unstable distribution (sid), these problems have been fixed in
version 1:4.2.8p4+dfsg-3.

We recommend that you upgrade your ntp packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered
in the Network Time Protocol daemon and utility programs:

CVE-2015-5146
A flaw was found in the way ntpd processed certain remote
configuration packets. An attacker could use a specially crafted
package to cause ntpd to crash if:

ntpd enabled remote configurationThe attacker had the knowledge of the configuration
password...The attacker had access to a computer entrusted to perform remote
configuration
Note that remote configuration is disabled by default in NTP.

CVE-2015-5194
It was found that ntpd could crash due to an uninitialized
variable when processing malformed logconfig configuration
commands.

Description truncated. Please see the references for more information." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p5+dfsg-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntp-doc", ver: "1:4.2.6.p5+dfsg-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntpdate", ver: "1:4.2.6.p5+dfsg-7+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.8p4+dfsg-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntp-doc", ver: "1:4.2.8p4+dfsg-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntpdate", ver: "1:4.2.8p4+dfsg-3", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p5+dfsg-2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntp-doc", ver: "1:4.2.6.p5+dfsg-2+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ntpdate", ver: "1:4.2.6.p5+dfsg-2+deb7u6", rls: "DEB7" ) ) != NULL){
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

