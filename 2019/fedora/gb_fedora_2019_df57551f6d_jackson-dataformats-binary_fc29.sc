if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876032" );
	script_version( "2021-09-01T10:01:36+0000" );
	script_cve_id( "CVE-2018-14718", "CVE-2018-14719", "CVE-2018-19360", "CVE-2018-19361", "CVE-2018-19362", "CVE-2018-12022", "CVE-2018-12023", "CVE-2018-14720", "CVE-2018-14721", "CVE-2016-7051", "CVE-2018-1000873" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 10:01:36 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-21 15:30:00 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:32:28 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for jackson-dataformats-binary FEDORA-2019-df57551f6d" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-df57551f6d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DMHN3SHBI6L2QLU2K3KNST6RHQN2VVCH" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jackson-dataformats-binary'
  package(s) announced via the FEDORA-2019-df57551f6d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Parent pom for Jackson binary dataformats." );
	script_tag( name: "affected", value: "'jackson-dataformats-binary' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "jackson-dataformats-binary", rpm: "jackson-dataformats-binary~2.9.8~1.fc29", rls: "FC29" ) )){
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
