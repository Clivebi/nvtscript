if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703371" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-5260", "CVE-2015-5261" );
	script_name( "Debian Security Advisory DSA 3371-1 (spice - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-09 00:00:00 +0200 (Fri, 09 Oct 2015)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3371.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "spice on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), these problems have been fixed
in version 0.11.0-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed in
version 0.12.5-1+deb8u2.

For the unstable distribution (sid), these problems have been fixed in
version 0.12.5-1.3.

We recommend that you upgrade your spice packages." );
	script_tag( name: "summary", value: "Frediano Ziglio of Red Hat discovered several vulnerabilities in spice,
a SPICE protocol client and server library. A malicious guest can
exploit these flaws to cause a denial of service (QEMU process crash),
execute arbitrary code on the host with the privileges of the hosting
QEMU process or read and write arbitrary memory locations on the host." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libspice-server-dev", ver: "0.11.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server1", ver: "0.11.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spice-client", ver: "0.11.0-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server-dev", ver: "0.12.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server1", ver: "0.12.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libspice-server1-dbg", ver: "0.12.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spice-client", ver: "0.12.5-1+deb8u2", rls: "DEB8" ) ) != NULL){
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

