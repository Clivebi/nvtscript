if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702885" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-2525" );
	script_name( "Debian Security Advisory DSA 2885-1 (libyaml-libyaml-perl - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-26 00:00:00 +0100 (Wed, 26 Mar 2014)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2885.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "libyaml-libyaml-perl on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 0.33-1+squeeze3.

For the stable distribution (wheezy), this problem has been fixed in
version 0.38-3+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 0.41-5.

We recommend that you upgrade your libyaml-libyaml-perl packages." );
	script_tag( name: "summary", value: "Ivan Fratric of the Google Security Team discovered a heap-based buffer
overflow vulnerability in LibYAML, a fast YAML 1.1 parser and emitter
library. A remote attacker could provide a specially-crafted YAML
document that, when parsed by an application using libyaml, would cause
the application to crash or, potentially, execute arbitrary code with
the privileges of the user running the application.

This update corrects this flaw in the copy that is embedded in the
libyaml-libyaml-perl package." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libyaml-libyaml-perl", ver: "0.33-1+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libyaml-libyaml-perl", ver: "0.38-3+deb7u2", rls: "DEB7" ) ) != NULL){
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

