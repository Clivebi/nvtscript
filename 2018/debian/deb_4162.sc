if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704162" );
	script_version( "2021-06-21T03:34:17+0000" );
	script_cve_id( "CVE-2018-5205", "CVE-2018-5206", "CVE-2018-5207", "CVE-2018-5208", "CVE-2018-7050", "CVE-2018-7051", "CVE-2018-7052", "CVE-2018-7053", "CVE-2018-7054" );
	script_name( "Debian Security Advisory DSA 4162-1 (irssi - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-01 00:00:00 +0200 (Sun, 01 Apr 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-12 12:21:00 +0000 (Tue, 12 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4162.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "irssi on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 1.0.7-1~deb9u1.

We recommend that you upgrade your irssi packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/irssi" );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in Irssi, a terminal-based
IRC client which can result in denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "irssi", ver: "1.0.7-1~deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "irssi-dev", ver: "1.0.7-1~deb9u1", rls: "DEB9" ) )){
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

