if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702936" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0749" );
	script_name( "Debian Security Advisory DSA 2936-1 (torque - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-23 00:00:00 +0200 (Fri, 23 May 2014)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2936.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "torque on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 2.4.8+dfsg-9squeeze4.

For the stable distribution (wheezy), this problem has been fixed in
version 2.4.16+dfsg-1+deb7u3.

For the unstable distribution (sid), this problem has been fixed in
version 2.4.16+dfsg-1.4.

We recommend that you upgrade your torque packages." );
	script_tag( name: "summary", value: "John Fitzpatrick from MWR Labs reported a stack-based buffer overflow
vulnerability in torque, a PBS-derived batch processing queueing system.
An unauthenticated remote attacker could exploit this flaw to execute
arbitrary code with root privileges." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libtorque2", ver: "2.4.8+dfsg-9squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtorque2-dev", ver: "2.4.8+dfsg-9squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-client", ver: "2.4.8+dfsg-9squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-client-x11", ver: "2.4.8+dfsg-9squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-common", ver: "2.4.8+dfsg-9squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-mom", ver: "2.4.8+dfsg-9squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-pam", ver: "2.4.8+dfsg-9squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-scheduler", ver: "2.4.8+dfsg-9squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-server", ver: "2.4.8+dfsg-9squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtorque2", ver: "2.4.16+dfsg-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtorque2-dev", ver: "2.4.16+dfsg-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-client", ver: "2.4.16+dfsg-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-client-x11", ver: "2.4.16+dfsg-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-common", ver: "2.4.16+dfsg-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-mom", ver: "2.4.16+dfsg-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-pam", ver: "2.4.16+dfsg-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-scheduler", ver: "2.4.16+dfsg-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-server", ver: "2.4.16+dfsg-1+deb7u3", rls: "DEB7" ) ) != NULL){
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

