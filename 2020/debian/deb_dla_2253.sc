if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892253" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2019-13033" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-03 03:15:00 +0000 (Fri, 03 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-06-22 03:00:11 +0000 (Mon, 22 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for lynis (DLA-2253-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00024.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2253-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/963161" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lynis'
  package(s) announced via the DLA-2253-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a vulnerability in lynis, a security
auditing tool. The license key could be obtained by simple
observation of the process list when a data upload is being
performed." );
	script_tag( name: "affected", value: "'lynis' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in lynis version
1.6.3-1+deb8u1.

We recommend that you upgrade your lynis packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "lynis", ver: "1.6.3-1+deb8u1", rls: "DEB8" ) )){
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

