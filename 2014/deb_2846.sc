if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702846" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-6458", "CVE-2014-1447" );
	script_name( "Debian Security Advisory DSA 2846-1 (libvirt - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-17 00:00:00 +0100 (Fri, 17 Jan 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:H/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2846.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libvirt on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 0.9.12.3-1. This bugfix point release also addresses some
additional bugfixes.

For the unstable distribution (sid), these problems have been fixed in
version 1.2.1-1.

We recommend that you upgrade your libvirt packages." );
	script_tag( name: "summary", value: "Multiple security issues have been found in Libvirt, a virtualisation
abstraction library:

CVE-2013-6458
It was discovered that insecure job usage could lead to denial of
service against libvirtd.

CVE-2014-1447
It was discovered that a race condition in keepalive handling could
lead to denial of service against libvirtd." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "0.9.12.3-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-dev", ver: "0.9.12.3-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-doc", ver: "0.9.12.3-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt0", ver: "0.9.12.3-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt0-dbg", ver: "0.9.12.3-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libvirt", ver: "0.9.12.3-1", rls: "DEB7" ) ) != NULL){
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

