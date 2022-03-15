if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891338" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-0492" );
	script_name( "Debian LTS: Security Advisory for beep (DLA-1338-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-03 00:00:00 +0200 (Tue, 03 Apr 2018)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-14 18:43:00 +0000 (Thu, 14 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/04/msg00002.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "beep on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', this issue has been fixed in beep version
1.3-3+deb7u1.

We recommend that you upgrade your beep packages." );
	script_tag( name: "summary", value: "It was discovered that there was a local privilege escalation
vulnerability in beep, an 'advanced PC speaker beeper'." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "beep", ver: "1.3-3+deb7u1", rls: "DEB7" ) )){
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

