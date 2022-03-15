if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876586" );
	script_version( "2021-09-01T11:01:35+0000" );
	script_cve_id( "CVE-2019-12817", "CVE-2019-11477", "CVE-2019-11479", "CVE-2019-11478", "CVE-2019-10126", "CVE-2019-12614", "CVE-2019-12456", "CVE-2019-12455", "CVE-2019-12454", "CVE-2019-12378", "CVE-2019-3846", "CVE-2019-12380", "CVE-2019-12381", "CVE-2019-12382", "CVE-2019-12379", "CVE-2019-11833", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091", "CVE-2019-11884", "CVE-2019-3900", "CVE-2019-9503", "CVE-2019-9500", "CVE-2019-3882", "CVE-2019-9857", "CVE-2019-8980", "CVE-2019-8912", "CVE-2019-7221", "CVE-2019-6974", "CVE-2019-7222", "CVE-2018-16880", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-3701", "CVE-2018-19824", "CVE-2018-16862", "CVE-2018-19407", "CVE-2019-13272" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 11:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 14:37:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-07-20 02:14:42 +0000 (Sat, 20 Jul 2019)" );
	script_name( "Fedora Update for kernel FEDORA-2019-a95015e60f" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-a95015e60f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OGRK5LYWBJ4E4SRI4DKX367NHYSI3VOH" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the FEDORA-2019-a95015e60f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The kernel meta package" );
	script_tag( name: "affected", value: "'kernel' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~5.1.18~200.fc29", rls: "FC29" ) )){
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

