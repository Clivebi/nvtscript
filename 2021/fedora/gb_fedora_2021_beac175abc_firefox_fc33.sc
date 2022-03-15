if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879601" );
	script_version( "2021-08-20T06:00:57+0000" );
	script_cve_id( "CVE-2021-29952" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 06:00:57 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-25 20:19:00 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-15 03:09:19 +0000 (Sat, 15 May 2021)" );
	script_name( "Fedora: Security Advisory for firefox (FEDORA-2021-beac175abc)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-beac175abc" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UHCYTFPM2WSESFM2IDMVTF4FQU4CTIER" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the FEDORA-2021-beac175abc advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability." );
	script_tag( name: "affected", value: "'firefox' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "firefox", rpm: "firefox~88.0.1~1.fc33", rls: "FC33" ) )){
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

