if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703103" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-9130" );
	script_name( "Debian Security Advisory DSA 3103-1 (libyaml-libyaml-perl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-12-13 00:00:00 +0100 (Sat, 13 Dec 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3103.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libyaml-libyaml-perl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 0.38-3+deb7u3.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 0.41-6.

For the unstable distribution (sid), this problem has been fixed in
version 0.41-6.

We recommend that you upgrade your libyaml-libyaml-perl packages." );
	script_tag( name: "summary", value: "Jonathan Gray and Stanislaw Pitucha
found an assertion failure in the way wrapped strings are parsed in LibYAML,
a fast YAML 1.1 parser and emitter library. An attacker able to load specially
crafted YAML input into an application using libyaml could cause the application
to crash.

This update corrects this flaw in the copy that is embedded in the
libyaml-libyaml-perl package." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libyaml-libyaml-perl", ver: "0.38-3+deb7u3", rls: "DEB7" ) ) != NULL){
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

