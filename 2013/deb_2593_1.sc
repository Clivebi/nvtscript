if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702593" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-6082", "CVE-2012-6495", "CVE-2012-6080", "CVE-2012-6081" );
	script_name( "Debian Security Advisory DSA 2593-1 (moin - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2593.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "moin on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 1.9.3-1+squeeze4.

For the unstable distribution (sid), this problem has been fixed in
version 1.9.5-4.

We recommend that you upgrade your moin packages." );
	script_tag( name: "summary", value: "It was discovered that missing input validation in the twikidraw and
anywikidraw actions can result in the execution of arbitrary code.
This security issue is being actively exploited.

This update also addresses path traversal in AttachFile." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-moinmoin", ver: "1.9.3-1+squeeze4", rls: "DEB6" ) ) != NULL){
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

