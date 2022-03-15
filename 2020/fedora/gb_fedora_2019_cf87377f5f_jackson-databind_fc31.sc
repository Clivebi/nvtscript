if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877322" );
	script_version( "2021-07-20T02:00:49+0000" );
	script_cve_id( "CVE-2019-14540", "CVE-2019-16335", "CVE-2019-16942", "CVE-2019-16943" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-20 02:00:49 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-22 21:38:00 +0000 (Mon, 22 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:38:04 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for jackson-databind FEDORA-2019-cf87377f5f" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-cf87377f5f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/A5OXHI43AG2UWCSTYYTASAVK2VIHIJDS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jackson-databind'
  package(s) announced via the FEDORA-2019-cf87377f5f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The general-purpose data-binding functionality and tree-model for Jackson Data
Processor. It builds on core streaming parser/generator package, and uses
Jackson Annotations for configuration." );
	script_tag( name: "affected", value: "'jackson-databind' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "jackson-databind", rpm: "jackson-databind~2.10.0~1.fc31", rls: "FC31" ) )){
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

