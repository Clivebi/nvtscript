if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703784" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_cve_id( "CVE-2017-5938" );
	script_name( "Debian Security Advisory DSA 3784-1 (viewvc - security update)" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-09 00:00:00 +0100 (Thu, 09 Feb 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3784.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "viewvc on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1.1.22-1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 1.1.26-1.

We recommend that you upgrade your viewvc packages." );
	script_tag( name: "summary", value: "Thomas Gerbet discovered that viewvc,
a web interface for CVS and Subversion repositories, did not properly sanitize
user input. This problem resulted in a potential Cross-Site Scripting
vulnerability." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "viewvc", ver: "1.1.22-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "viewvc-query", ver: "1.1.22-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

