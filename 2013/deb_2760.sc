if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702760" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-4502", "CVE-2012-4503" );
	script_name( "Debian Security Advisory DSA 2760-1 (chrony - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 00:00:00 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2760.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "chrony on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems will be fixed
soon in 1.24-3+squeeze1 (due to a technical restriction in the archive
processing scripts the two updates cannot be released together).

For the stable distribution (wheezy), these problems have been fixed in
version 1.24-3.1+deb7u2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your chrony packages." );
	script_tag( name: "summary", value: "Florian Weimer discovered two security problems in the Chrony time
synchronisation software (buffer overflows and use of uninitialised data
in command replies)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chrony", ver: "1.24-3.1+deb7u2", rls: "DEB7" ) ) != NULL){
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

