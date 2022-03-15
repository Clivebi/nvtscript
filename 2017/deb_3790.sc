if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703790" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2016-9577", "CVE-2016-9578" );
	script_name( "Debian Security Advisory DSA 3790-1 (spice - security update)" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-16 00:00:00 +0100 (Thu, 16 Feb 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3790.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "spice on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 0.12.5-1+deb8u4.

For the unstable distribution (sid), these problems have been fixed in
version 0.12.8-2.1.

We recommend that you upgrade your spice packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in spice, a SPICE protocol
client and server library. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2016-9577
Frediano Ziglio of Red Hat discovered a buffer overflow
vulnerability in the main_channel_alloc_msg_rcv_buf function. An
authenticated attacker can take advantage of this flaw to cause a
denial of service (spice server crash), or possibly, execute
arbitrary code.

CVE-2016-9578
Frediano Ziglio of Red Hat discovered that spice does not properly
validate incoming messages. An attacker able to connect to the
spice server could send crafted messages which would cause the
process to crash." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libspice-server-dev", ver: "0.12.5-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server1:amd64", ver: "0.12.5-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server1:i386", ver: "0.12.5-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server1-dbg:amd64", ver: "0.12.5-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server1-dbg:i386", ver: "0.12.5-1+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spice-client", ver: "0.12.5-1+deb8u4", rls: "DEB8" ) ) != NULL){
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

