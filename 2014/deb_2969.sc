if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702969" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0477" );
	script_name( "Debian Security Advisory DSA 2969-1 (libemail-address-perl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-27 00:00:00 +0200 (Fri, 27 Jun 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2969.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libemail-address-perl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1.895-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 1.905-1.

For the unstable distribution (sid), this problem has been fixed in
version 1.905-1.

We recommend that you upgrade your libemail-address-perl packages." );
	script_tag( name: "summary", value: "Bastian Blank reported a denial of service vulnerability in
Email::Address, a Perl module for RFC 2822 address parsing and creation.
Email::Address::parse used significant time on parsing empty quoted
strings. A remote attacker able to supply specifically crafted input to
an application using Email::Address for parsing, could use this flaw to
mount a denial of service attack against the application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libemail-address-perl", ver: "1.895-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

