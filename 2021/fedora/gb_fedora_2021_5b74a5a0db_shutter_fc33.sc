if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817753" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2016-10081" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)" );
	script_tag( name: "creation_date", value: "2021-08-30 01:08:48 +0000 (Mon, 30 Aug 2021)" );
	script_name( "Fedora: Security Advisory for shutter (FEDORA-2021-5b74a5a0db)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-5b74a5a0db" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4QG54GTU45KBIQJLU4WREG4G4JJEUTEJ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'shutter'
  package(s) announced via the FEDORA-2021-5b74a5a0db advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Shutter is a feature-rich screenshot program for Linux based operating systems
such as Ubuntu. You can take a screenshot of a specific area, window, your whole
screen, or even of a website  apply different effects to it, draw on it to
highlight points, and then upload to an image hosting site, all within one
window. Shutter is free, open-source, and licensed under GPL v3." );
	script_tag( name: "affected", value: "'shutter' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "shutter", rpm: "shutter~0.98~5.fc33", rls: "FC33" ) )){
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
