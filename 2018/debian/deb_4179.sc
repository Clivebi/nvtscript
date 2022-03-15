if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704179" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2017-5715" );
	script_name( "Debian Security Advisory DSA 4179-1 (linux-tools - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-24 00:00:00 +0200 (Tue, 24 Apr 2018)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 14:52:00 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4179.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "linux-tools on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 3.16.56-1.

We recommend that you upgrade your linux-tools packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/linux-tools" );
	script_tag( name: "summary", value: "This update doesn't fix a vulnerability in linux-tools, but provides
support for building Linux kernel modules with the retpoline mitigation for CVE-2017-5715
(Spectre variant 2).

This update also includes bug fixes from the upstream Linux 3.16 stable
branch up to and including 3.16.56." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "hyperv-daemons", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-kbuild-3.16", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-tools-3.16", ver: "3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libusbip-dev", ver: "2.0+3.16.56-1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "usbip", ver: "2.0+3.16.56-1", rls: "DEB8" ) )){
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

