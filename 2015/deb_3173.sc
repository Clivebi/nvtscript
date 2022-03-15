if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703173" );
	script_version( "$Revision: 14278 $" );
	script_name( "Debian Security Advisory DSA 3173-1 (libgtk2-perl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-25 00:00:00 +0100 (Wed, 25 Feb 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3173.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libgtk2-perl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 2:1.244-1+deb7u1.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 2:1.2492-4.

For the unstable distribution (sid), this problem has been fixed in
version 2:1.2492-4.

We recommend that you upgrade your libgtk2-perl packages." );
	script_tag( name: "summary", value: "It was discovered that libgtk2-perl,
a Perl interface to the 2.x series of the Gimp Toolkit library, incorrectly
frees memory which GTK+ still holds onto and might access later, leading to
denial of service (application crash) or, potentially, to arbitrary code
execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libgtk2-perl", ver: "2:1.244-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgtk2-perl-doc", ver: "2:1.244-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

