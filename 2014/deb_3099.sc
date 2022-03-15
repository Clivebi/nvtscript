if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703099" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-3636", "CVE-2014-7824" );
	script_name( "Debian Security Advisory DSA 3099-1 (dbus - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-12-11 00:00:00 +0100 (Thu, 11 Dec 2014)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3099.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "dbus on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problem have been fixed in version 1.6.8-1+deb7u5.

For the upcoming stable distribution (jessie) and the unstable
distribution (sid), these problem have been fixed in version 1.8.10-1.

We recommend that you upgrade your dbus packages." );
	script_tag( name: "summary", value: "Simon McVittie discovered that the fix for
CVE-2014-3636
was incorrect, as it did not fully address the underlying
denial-of-service vector. This update starts the D-Bus daemon as root
initially, so that it can properly raise its file descriptor count.

In addition, this update reverts the auth_timeout change in the
previous security update to its old value because the new value causes
boot failures on some systems. See the README.Debian file for details
how to harden the D-Bus daemon against malicious local users." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dbus", ver: "1.6.8-1+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-1-dbg", ver: "1.6.8-1+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-1-doc", ver: "1.6.8-1+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-x11", ver: "1.6.8-1+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdbus-1-3", ver: "1.6.8-1+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdbus-1-dev", ver: "1.6.8-1+deb7u5", rls: "DEB7" ) ) != NULL){
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

