if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703357" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-6927" );
	script_name( "Debian Security Advisory DSA 3357-1 (vzctl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-09-13 00:00:00 +0200 (Sun, 13 Sep 2015)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3357.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "vzctl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 4.8-1+deb8u2. During the update existing configurations are
automatically updated.

For the testing distribution (stretch), this problem has been fixed
in version 4.9.4-2.

For the unstable distribution (sid), this problem has been fixed in
version 4.9.4-2.

We recommend that you upgrade your vzctl packages." );
	script_tag( name: "summary", value: "It was discovered that vzctl, a set of control tools for the OpenVZ
server virtualisation solution, determined the storage layout of
containers based on the presence of an XML file inside the container.
An attacker with local root privileges in a simfs-based container
could gain control over ploop-based containers. Further information on
the prerequisites of such an attack can be found at src.openvz.org.

The oldstable distribution (wheezy) is not affected." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "vzctl", ver: "4.8-1+deb8u2", rls: "DEB8" ) ) != NULL){
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

