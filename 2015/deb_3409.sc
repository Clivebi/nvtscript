if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703409" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-5309" );
	script_name( "Debian Security Advisory DSA 3409-1 (putty - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-01 00:00:00 +0100 (Tue, 01 Dec 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3409.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|9|8)" );
	script_tag( name: "affected", value: "putty on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 0.62-9+deb7u3.

For the stable distribution (jessie), this problem has been fixed in
version 0.63-10+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 0.66-1.

For the unstable distribution (sid), this problem has been fixed in
version 0.66-1.

We recommend that you upgrade your putty packages." );
	script_tag( name: "summary", value: "A memory-corrupting integer
overflow in the handling of the ECH (erase characters) control sequence was
discovered in PuTTY's terminal emulator. A remote attacker can take advantage
of this flaw to mount a denial of service or potentially to execute arbitrary
code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "pterm", ver: "0.62-9+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty", ver: "0.62-9+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty-doc", ver: "0.62-9+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty-tools", ver: "0.62-9+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pterm", ver: "0.66-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty", ver: "0.66-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty-doc", ver: "0.66-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty-tools", ver: "0.66-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pterm", ver: "0.63-10+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty", ver: "0.63-10+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty-doc", ver: "0.63-10+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty-tools", ver: "0.63-10+deb8u1", rls: "DEB8" ) ) != NULL){
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

