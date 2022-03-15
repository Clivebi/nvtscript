if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704234" );
	script_version( "2021-06-18T11:51:03+0000" );
	script_cve_id( "CVE-2018-12564", "CVE-2018-12565" );
	script_name( "Debian Security Advisory DSA 4234-1 (lava-server - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:51:03 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-22 00:00:00 +0200 (Fri, 22 Jun 2018)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-18 21:00:00 +0000 (Wed, 18 Sep 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4234.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "lava-server on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 2016.12-3.

We recommend that you upgrade your lava-server packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/lava-server" );
	script_tag( name: "summary", value: "Two vulnerabilities were discovered in LAVA, a continuous integration
system for deploying operating systems for running tests, which could
result in information disclosure of files readable by the lavaserver
system user or the execution of arbitrary code via a XMLRPC call." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "lava", ver: "2016.12-3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lava-dev", ver: "2016.12-3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lava-server", ver: "2016.12-3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lava-server-doc", ver: "2016.12-3", rls: "DEB9" ) )){
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

