if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877113" );
	script_version( "2021-07-19T02:00:45+0000" );
	script_cve_id( "CVE-2019-19074", "CVE-2019-19073", "CVE-2019-19072", "CVE-2019-19071", "CVE-2019-19070", "CVE-2019-19068", "CVE-2019-19043", "CVE-2019-19066", "CVE-2019-19046", "CVE-2019-19050", "CVE-2019-19062", "CVE-2019-19064", "CVE-2019-19063", "CVE-2019-19059", "CVE-2019-19058", "CVE-2019-19057", "CVE-2019-19053", "CVE-2019-19056", "CVE-2019-19055", "CVE-2019-19054", "CVE-2019-11135", "CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-19 02:00:45 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:25:58 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for kernel FEDORA-2019-34a75d7e61" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-34a75d7e61" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PY7LJMSPAGRIKABJPDKQDTXYW3L5RX2T" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the FEDORA-2019-34a75d7e61 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The kernel meta package" );
	script_tag( name: "affected", value: "'kernel' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~5.3.12~300.fc31", rls: "FC31" ) )){
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

