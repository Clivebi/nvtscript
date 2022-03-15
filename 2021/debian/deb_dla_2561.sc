if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892561" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2021-21289" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-08 07:15:00 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-02-17 04:00:08 +0000 (Wed, 17 Feb 2021)" );
	script_name( "Debian LTS: Security Advisory for ruby-mechanize (DLA-2561-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/02/msg00021.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2561-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2561-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-mechanize'
  package(s) announced via the DLA-2561-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mechanize is an open-source Ruby library that makes automated web
interaction easy. In Mechanize, from v2.0.0 until v2.7.7, there
is a command injection vulnerability.

Affected versions of Mechanize allow for OS commands to be
injected using several classes' methods which implicitly use
Ruby's Kernel#open method." );
	script_tag( name: "affected", value: "'ruby-mechanize' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
2.7.5-1+deb9u1.

We recommend that you upgrade your ruby-mechanize packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-mechanize", ver: "2.7.5-1+deb9u1", rls: "DEB9" ) )){
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
exit( 0 );

