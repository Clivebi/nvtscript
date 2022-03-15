if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892120" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-8130" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-30 14:00:00 +0000 (Tue, 30 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-02-27 04:00:11 +0000 (Thu, 27 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for rake (DLA-2120-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00026.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2120-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rake'
  package(s) announced via the DLA-2120-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "There is an OS command injection vulnerability in Rake (a ruby make-like
utility) < 12.3.3 in Rake::FileList when supplying a filename that
begins with the pipe character ." );
	script_tag( name: "affected", value: "'rake' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
10.3.2-2+deb8u1.

We recommend that you upgrade your rake packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "rake", ver: "10.3.2-2+deb8u1", rls: "DEB8" ) )){
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

