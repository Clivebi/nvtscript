if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876324" );
	script_version( "2021-09-01T08:01:24+0000" );
	script_cve_id( "CVE-2019-9903", "CVE-2019-11026", "CVE-2018-13988", "CVE-2017-18267" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 08:01:24 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-08 02:10:53 +0000 (Wed, 08 May 2019)" );
	script_name( "Fedora Update for poppler FEDORA-2019-3193a75b06" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-3193a75b06" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XGYLZZ4DZUDBQEGCNDWSZPSFNNZJF4S6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'poppler'
  package(s) announced via the FEDORA-2019-3193a75b06 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "poppler is a PDF rendering library." );
	script_tag( name: "affected", value: "'poppler' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "poppler", rpm: "poppler~0.62.0~22.fc28", rls: "FC28" ) )){
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

