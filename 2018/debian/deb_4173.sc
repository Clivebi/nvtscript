if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704173" );
	script_version( "2021-06-16T02:47:07+0000" );
	script_cve_id( "CVE-2017-12110", "CVE-2017-12111", "CVE-2017-2896", "CVE-2017-2897", "CVE-2017-2919" );
	script_name( "Debian Security Advisory DSA 4173-1 (r-cran-readxl - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:47:07 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-16 00:00:00 +0200 (Mon, 16 Apr 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-18 01:29:00 +0000 (Wed, 18 Apr 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4173.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "r-cran-readxl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 0.1.1-1+deb9u1.

We recommend that you upgrade your r-cran-readxl packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/r-cran-readxl" );
	script_tag( name: "summary", value: "Marcin Noga discovered multiple vulnerabilities in readxl, a GNU R
package to read Excel files (via the integrated libxls library), which
could result in the execution of arbitrary code if a malformed
spreadsheet is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "r-cran-readxl", ver: "0.1.1-1+deb9u1", rls: "DEB9" ) )){
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

