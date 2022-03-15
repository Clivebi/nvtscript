if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876158" );
	script_version( "2021-09-01T11:01:35+0000" );
	script_cve_id( "CVE-2019-7577", "CVE-2019-7575", "CVE-2019-7574", "CVE-2019-7572", "CVE-2019-7573", "CVE-2019-7576", "CVE-2019-7578", "CVE-2019-7638", "CVE-2019-7636", "CVE-2019-7637", "CVE-2019-7635" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 11:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-22 15:01:00 +0000 (Mon, 22 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:37:03 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for SDL FEDORA-2019-7a554204c1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-7a554204c1" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OHEXXGCOKNICFBDMNVYYDTSDLQ42K5G5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'SDL'
  package(s) announced via the FEDORA-2019-7a554204c1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Simple DirectMedia Layer (SDL) is a cross-platform multimedia library designed
to provide fast access to the graphics frame buffer and audio device." );
	script_tag( name: "affected", value: "'SDL' package(s) on Fedora 29." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "SDL", rpm: "SDL~1.2.15~36.fc29", rls: "FC29" ) )){
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
}
exit( 0 );

