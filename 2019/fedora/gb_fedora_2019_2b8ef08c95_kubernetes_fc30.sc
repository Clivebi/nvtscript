if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876720" );
	script_version( "2021-09-01T14:01:32+0000" );
	script_cve_id( "CVE-2019-11250", "CVE-2019-1002101", "CVE-2019-11248", "CVE-2019-11249", "CVE-2019-11246", "CVE-2019-11247" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 14:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-02 16:21:00 +0000 (Fri, 02 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-08-27 02:32:41 +0000 (Tue, 27 Aug 2019)" );
	script_name( "Fedora Update for kubernetes FEDORA-2019-2b8ef08c95" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-2b8ef08c95" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QZB7E3DOZ5WDG46XAIU6K32CXHXPXB2F" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kubernetes'
  package(s) announced via the FEDORA-2019-2b8ef08c95 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Container cluster management" );
	script_tag( name: "affected", value: "'kubernetes' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "kubernetes", rpm: "kubernetes~1.15.2~1.fc30", rls: "FC30" ) )){
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

