if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702770" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4319" );
	script_name( "Debian Security Advisory DSA 2770-1 (torque - authentication bypass)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-10-09 00:00:00 +0200 (Wed, 09 Oct 2013)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2770.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "torque on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 2.4.8+dfsg-9squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 2.4.16+dfsg-1+deb7u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your torque packages." );
	script_tag( name: "summary", value: "John Fitzpatrick of MWR InfoSecurity discovered an authentication bypass
vulnerability in torque, a PBS-derived batch processing queueing system.

The torque authentication model revolves around the use of privileged
ports. If a request is not made from a privileged port then it is
assumed not to be trusted or authenticated. It was found that pbs_mom
does not perform a check to ensure that connections are established
from a privileged port.

A user who can run jobs or login to a node running pbs_server or pbs_mom
can exploit this vulnerability to remotely execute code as root on the
cluster by submitting a command directly to a pbs_mom daemon
to queue and run a job." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libtorque2", ver: "2.4.8+dfsg-9squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtorque2-dev", ver: "2.4.8+dfsg-9squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-client", ver: "2.4.8+dfsg-9squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-client-x11", ver: "2.4.8+dfsg-9squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-common", ver: "2.4.8+dfsg-9squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-mom", ver: "2.4.8+dfsg-9squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-pam", ver: "2.4.8+dfsg-9squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-scheduler", ver: "2.4.8+dfsg-9squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-server", ver: "2.4.8+dfsg-9squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtorque2", ver: "2.4.16+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libtorque2-dev", ver: "2.4.16+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-client", ver: "2.4.16+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-client-x11", ver: "2.4.16+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-common", ver: "2.4.16+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-mom", ver: "2.4.16+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-pam", ver: "2.4.16+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-scheduler", ver: "2.4.16+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "torque-server", ver: "2.4.16+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

