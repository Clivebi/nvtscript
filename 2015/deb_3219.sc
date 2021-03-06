if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703219" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-2788" );
	script_name( "Debian Security Advisory DSA 3219-1 (libdbd-firebird-perl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-11 00:00:00 +0200 (Sat, 11 Apr 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3219.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libdbd-firebird-perl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 0.91-2+deb7u1.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 1.18-2.

For the unstable distribution (sid), this problem has been fixed in
version 1.18-2.

We recommend that you upgrade your libdbd-firebird-perl packages." );
	script_tag( name: "summary", value: "Stefan Roas discovered a way to cause
a buffer overflow in DBD-FireBird, a Perl DBI driver for the Firebird RDBMS, in
certain error conditions, due to the use of the sprintf() function to write to
a fixed-size memory buffer." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libdbd-firebird-perl", ver: "0.91-2+deb7u1", rls: "DEB7" ) ) != NULL){
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

