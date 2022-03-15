if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702707" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-2168" );
	script_name( "Debian Security Advisory DSA 2707-1 (dbus - denial of service)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-06-13 00:00:00 +0200 (Thu, 13 Jun 2013)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2707.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "dbus on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1.6.8-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 1.6.12-1.

For the unstable distribution (sid), this problem has been fixed in
version 1.6.12-1.

We recommend that you upgrade your dbus packages." );
	script_tag( name: "summary", value: "Alexandru Cornea discovered a vulnerability in libdbus caused by an
implementation bug in _dbus_printf_string_upper_bound(). This
vulnerability can be exploited by a local user to crash system services
that use libdbus, causing denial of service. Depending on the dbus
services running, it could lead to complete system crash.

The oldstable distribution (squeeze) is not affected by this problem." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dbus", ver: "1.6.8-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-1-dbg", ver: "1.6.8-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-1-doc", ver: "1.6.8-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dbus-x11", ver: "1.6.8-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdbus-1-3", ver: "1.6.8-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdbus-1-dev", ver: "1.6.8-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

