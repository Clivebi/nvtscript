if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876545" );
	script_version( "2021-09-01T08:01:24+0000" );
	script_cve_id( "CVE-2017-18219", "CVE-2017-18220", "CVE-2018-6799", "CVE-2017-14504", "CVE-2017-14649", "CVE-2017-14733", "CVE-2017-14994", "CVE-2017-14997", "CVE-2017-15238", "CVE-2017-15930", "CVE-2017-16545", "CVE-2017-16547", "CVE-2017-17498", "CVE-2017-17500", "CVE-2017-17501", "CVE-2017-17502", "CVE-2017-17503", "CVE-2017-11638", "CVE-2017-11642", "CVE-2017-11722", "CVE-2017-12935", "CVE-2017-12936", "CVE-2017-12937", "CVE-2017-13063", "CVE-2017-13064", "CVE-2017-13065", "CVE-2017-13648", "CVE-2017-13736", "CVE-2017-13737", "CVE-2017-13775", "CVE-2017-12805", "CVE-2017-12806", "CVE-2019-11470", "CVE-2019-11472", "CVE-2019-11474", "CVE-2019-11473" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 08:01:24 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-30 03:15:00 +0000 (Sun, 30 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-07-01 02:10:17 +0000 (Mon, 01 Jul 2019)" );
	script_name( "Fedora Update for GraphicsMagick FEDORA-2019-da4c20882c" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-da4c20882c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PF62B5PJA2JDUOCKJGUQO3SPL74BEYSV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the FEDORA-2019-da4c20882c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "GraphicsMagick is a comprehensive image processing package which is initially
based on ImageMagick 5.5.2, but which has undergone significant re-work by
the GraphicsMagick Group to significantly improve the quality and performance
of the software." );
	script_tag( name: "affected", value: "'GraphicsMagick' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "GraphicsMagick", rpm: "GraphicsMagick~1.3.32~1.fc30", rls: "FC30" ) )){
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

