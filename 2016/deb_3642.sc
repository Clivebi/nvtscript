if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703642" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-1000212" );
	script_name( "Debian Security Advisory DSA 3642-1 (lighttpd - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-05 00:00:00 +0200 (Fri, 05 Aug 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3642.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "lighttpd on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this
problem has been fixed in version 1.4.35-4+deb8u1.

We recommend that you upgrade your lighttpd packages." );
	script_tag( name: "summary", value: "Dominic Scheirlinck and Scott Geary of Vend
reported insecure behavior in the lighttpd web server. Lighttpd assigned Proxy header
values from client requests to internal HTTP_PROXY environment variables, allowing
remote attackers to carry out Man in the Middle (MITM) attacks or
initiate connections to arbitrary hosts." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "lighttpd", ver: "1.4.35-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-doc", ver: "1.4.35-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-cml", ver: "1.4.35-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-magnet", ver: "1.4.35-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-mysql-vhost", ver: "1.4.35-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-trigger-b4-dl", ver: "1.4.35-4+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-webdav", ver: "1.4.35-4+deb8u1", rls: "DEB8" ) ) != NULL){
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

