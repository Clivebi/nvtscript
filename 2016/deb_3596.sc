if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703596" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-0749", "CVE-2016-2150" );
	script_name( "Debian Security Advisory DSA 3596-1 (spice - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-06-06 00:00:00 +0200 (Mon, 06 Jun 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3596.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "spice on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these
problems have been fixed in version 0.12.5-1+deb8u3.

We recommend that you upgrade your spice packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in
spice, a SPICE protocol client and server library. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2016-0749
Jing Zhao of Red Hat discovered a memory allocation flaw, leading to
a heap-based buffer overflow in spice's smartcard interaction. A
user connecting to a guest VM via spice can take advantage of this
flaw to cause a denial-of-service (QEMU process crash), or
potentially to execute arbitrary code on the host with the
privileges of the hosting QEMU process.

CVE-2016-2150
Frediano Ziglio of Red Hat discovered that a malicious guest inside
a virtual machine can take control of the corresponding QEMU process
in the host using crafted primary surface parameters." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libspice-server-dev", ver: "0.12.5-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server1:amd64", ver: "0.12.5-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server1:i386", ver: "0.12.5-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server1-dbg:amd64", ver: "0.12.5-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server1-dbg:i386", ver: "0.12.5-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spice-client", ver: "0.12.5-1+deb8u3", rls: "DEB8" ) ) != NULL){
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

