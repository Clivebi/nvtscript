if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703379" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-6031" );
	script_name( "Debian Security Advisory DSA 3379-1 (miniupnpc - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-25 00:00:00 +0200 (Sun, 25 Oct 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3379.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "miniupnpc on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 1.5-2+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 1.9.20140610-2+deb8u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your miniupnpc packages." );
	script_tag( name: "summary", value: "Aleksandar Nikolic of Cisco Talos
discovered a buffer overflow vulnerability in the XML parser functionality of
miniupnpc, a UPnP IGD client lightweight library. A remote attacker can take
advantage of this flaw to cause an application using the miniupnpc library to
crash, or potentially to execute arbitrary code with the privileges of the user
running the application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libminiupnpc-dev", ver: "1.5-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libminiupnpc5", ver: "1.5-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "miniupnpc", ver: "1.5-2+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libminiupnpc-dev", ver: "1.9.20140610-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libminiupnpc10", ver: "1.9.20140610-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "miniupnpc", ver: "1.9.20140610-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-miniupnpc", ver: "1.9.20140610-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

