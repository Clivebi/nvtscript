if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891767" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-11454", "CVE-2019-11455" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-27 02:00:08 +0000 (Sat, 27 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for monit (DLA-1767-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/04/msg00028.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1767-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'monit'
  package(s) announced via the DLA-1767-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Zack Flack found several issues in monit, a utility for monitoring and
managing daemons or similar programs.

CVE-2019-11454
An XSS vulnerabilitty has been reported that could be prevented by
HTML escaping the log file content when viewed via Monit GUI.

CVE-2019-11455
A buffer overrun vulnerability has been reported in URL decoding." );
	script_tag( name: "affected", value: "'monit' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1:5.9-1+deb8u2.

We recommend that you upgrade your monit packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "monit", ver: "1:5.9-1+deb8u2", rls: "DEB8" ) )){
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

