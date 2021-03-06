if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703400" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-1335" );
	script_name( "Debian Security Advisory DSA 3400-1 (lxc - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-19 00:00:00 +0100 (Thu, 19 Nov 2015)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3400.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "lxc on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1:1.0.6-6+deb8u2.

We recommend that you upgrade your lxc packages." );
	script_tag( name: "summary", value: "Roman Fiedler discovered a directory
traversal flaw in LXC, the Linux Containers userspace tools. A local attacker
with access to a LXC container could exploit this flaw to run programs inside
the container that are not confined by AppArmor or expose unintended files in
the host to the container." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "lxc", ver: "1:1.0.6-6+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lxc-dbg", ver: "1:1.0.6-6+deb8u2", rls: "DEB8" ) ) != NULL){
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

