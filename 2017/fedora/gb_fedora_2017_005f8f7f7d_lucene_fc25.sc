if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.873561" );
	script_version( "2021-09-13T09:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 09:01:48 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-02 11:13:52 +0100 (Thu, 02 Nov 2017)" );
	script_cve_id( "CVE-2017-12629" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-18 16:15:00 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for lucene FEDORA-2017-005f8f7f7d" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lucene'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "lucene on Fedora 25" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-005f8f7f7d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GTE5P6CWLVBPWNLR3RMLZGEFUYCZZR5V" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC25" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC25"){
	if(( res = isrpmvuln( pkg: "lucene", rpm: "lucene~5.5.0~5.fc25", rls: "FC25" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

