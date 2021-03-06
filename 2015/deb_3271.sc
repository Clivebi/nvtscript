if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703271" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2013-7441", "CVE-2015-0847" );
	script_name( "Debian Security Advisory DSA 3271-1 (nbd - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-05-23 00:00:00 +0200 (Sat, 23 May 2015)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3271.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "nbd on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1:3.2-4~deb7u5.

For the stable distribution (jessie), these problems have been fixed in
version 1:3.8-4+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 1:3.10-1.

For the unstable distribution (sid), these problems have been fixed in
version 1:3.10-1.

We recommend that you upgrade your nbd packages." );
	script_tag( name: "summary", value: "Tuomas Rsnen discovered that
unsafe signal handling in nbd-server, the server for the Network Block Device
protocol, could allow remote attackers to cause a deadlock in the server process
and thus a denial of service.

Tuomas Rsnen also discovered that the modern-style negotiation was
carried out in the main server process before forking the actual client
handler. This could allow a remote attacker to cause a denial of service
(crash) by querying a non-existent export. This issue only affected the
oldstable distribution (wheezy)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "nbd-client", ver: "1:3.2-4~deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nbd-server", ver: "1:3.2-4~deb7u5", rls: "DEB7" ) ) != NULL){
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

