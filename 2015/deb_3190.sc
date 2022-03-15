if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703190" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-2157" );
	script_name( "Debian Security Advisory DSA 3190-1 (putty - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-15 00:00:00 +0100 (Sun, 15 Mar 2015)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3190.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "putty on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 0.62-9+deb7u2.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 0.63-10.

For the unstable distribution (sid), this problem has been fixed in
version 0.63-10.

We recommend that you upgrade your putty packages." );
	script_tag( name: "summary", value: "Patrick Coleman discovered
that the Putty SSH client failed to wipe out unused sensitive memory.

In addition Florent Daigniere discovered that exponential values in
Diffie Hellman exchanges were insufficienty restricted." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "pterm", ver: "0.62-9+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty", ver: "0.62-9+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty-doc", ver: "0.62-9+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "putty-tools", ver: "0.62-9+deb7u2", rls: "DEB7" ) ) != NULL){
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

