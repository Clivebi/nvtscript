if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.872856" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-14 15:55:25 +0530 (Fri, 14 Jul 2017)" );
	script_cve_id( "CVE-2017-9304", "CVE-2017-9465" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for yara FEDORA-2017-47487b1223" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'yara'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "yara on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-47487b1223" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Q4E2MCOOL72OJ4SSVXZSJYLEAJLXFNUC" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC24" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC24"){
	if(( res = isrpmvuln( pkg: "yara", rpm: "yara~3.6.2~1.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

