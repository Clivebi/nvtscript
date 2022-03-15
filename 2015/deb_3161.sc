if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703161" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-0245" );
	script_name( "Debian Security Advisory DSA 3161-1 (dbus - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-11 00:00:00 +0100 (Wed, 11 Feb 2015)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3161.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "dbus on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.6.8-1+deb7u6.

For the unstable distribution (sid), this problem has been fixed in
version 1.8.16-1.

We recommend that you upgrade your dbus packages." );
	script_tag( name: "summary", value: "Simon McVittie discovered a local
denial of service flaw in dbus, an asynchronous inter-process communication
system. On systems with systemd-style service activation, dbus-daemon does not
prevent forged ActivationFailure messages from non-root processes. A malicious
local user could use this flaw to trick dbus-daemon into thinking that systemd
failed to activate a system service, resulting in an error reply back to
the requester." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dbus", ver: "1.6.8-1+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-1-dbg", ver: "1.6.8-1+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-1-doc", ver: "1.6.8-1+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-x11", ver: "1.6.8-1+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdbus-1-3", ver: "1.6.8-1+deb7u6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdbus-1-dev", ver: "1.6.8-1+deb7u6", rls: "DEB7" ) ) != NULL){
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

