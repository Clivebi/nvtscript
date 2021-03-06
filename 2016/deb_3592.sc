if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703592" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_cve_id( "CVE-2016-4450" );
	script_name( "Debian Security Advisory DSA 3592-1 (nginx - security update)" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-01 00:00:00 +0200 (Wed, 01 Jun 2016)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 20:17:00 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3592.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "nginx on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1.6.2-5+deb8u2.

For the unstable distribution (sid), this problem has been fixed in
version 1.10.1-1.

We recommend that you upgrade your nginx packages." );
	script_tag( name: "summary", value: "It was discovered that a NULL pointer
dereference in the Nginx code responsible for saving client request bodies to a
temporary file might result in denial of service: Malformed requests could crash
worker processes." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "nginx", ver: "1.6.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-common", ver: "1.6.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-doc", ver: "1.6.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-extras", ver: "1.6.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-extras-dbg", ver: "1.6.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-full", ver: "1.6.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-full-dbg", ver: "1.6.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-light", ver: "1.6.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-light-dbg", ver: "1.6.2-5+deb8u2", rls: "DEB8" ) ) != NULL){
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

