if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702884" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-2525" );
	script_name( "Debian Security Advisory DSA 2884-1 (libyaml - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-26 00:00:00 +0100 (Wed, 26 Mar 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2884.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "libyaml on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 0.1.3-1+deb6u4.

For the stable distribution (wheezy), this problem has been fixed in
version 0.1.4-2+deb7u4.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your libyaml packages." );
	script_tag( name: "summary", value: "Ivan Fratric of the Google Security Team discovered a heap-based buffer
overflow vulnerability in LibYAML, a fast YAML 1.1 parser and emitter
library. A remote attacker could provide a specially-crafted YAML
document that, when parsed by an application using libyaml, would cause
the application to crash or, potentially, execute arbitrary code with
the privileges of the user running the application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libyaml-0-2", ver: "0.1.3-1+deb6u4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libyaml-dev", ver: "0.1.3-1+deb6u4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libyaml-0-2", ver: "0.1.4-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libyaml-0-2-dbg", ver: "0.1.4-2+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libyaml-dev", ver: "0.1.4-2+deb7u4", rls: "DEB7" ) ) != NULL){
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

