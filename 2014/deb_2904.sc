if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702904" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-0981", "CVE-2014-0983" );
	script_name( "Debian Security Advisory DSA 2904-1 (virtualbox - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-15 00:00:00 +0200 (Tue, 15 Apr 2014)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2904.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "virtualbox on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 3.2.10-dfsg-1+squeeze3.

For the stable distribution (wheezy), these problems have been fixed in
version 4.1.18-dfsg-2+deb7u3.

For the testing distribution (jessie), these problems have been fixed in
version 4.3.10-dfsg-1.

For the unstable distribution (sid), these problems have been fixed in
version 4.3.10-dfsg-1.

We recommend that you upgrade your virtualbox packages." );
	script_tag( name: "summary", value: "Francisco Falcon discovered that missing input sanitizing in the 3D
acceleration code in VirtualBox could lead to the execution of arbitrary
code on the host system." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "virtualbox", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-dbg", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-dkms", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-fuse", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-dkms", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-source", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-utils", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-x11", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-dbg", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-dkms", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-fuse", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-dkms", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-source", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-utils", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-x11", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-qt", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-source", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-qt", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-source", ver: "4.1.18-dfsg-2+deb7u3", rls: "DEB7" ) ) != NULL){
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

