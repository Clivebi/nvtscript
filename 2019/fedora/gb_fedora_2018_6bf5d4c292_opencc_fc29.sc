if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875973" );
	script_version( "2021-09-02T10:01:39+0000" );
	script_cve_id( "CVE-2018-16982" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-29 15:43:00 +0000 (Thu, 29 Nov 2018)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:30:14 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for opencc FEDORA-2018-6bf5d4c292" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2018-6bf5d4c292" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DBLYPSYQSR56D4GQT4GRZKJNNK5YWPSR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'opencc'
  package(s) announced via the FEDORA-2018-6bf5d4c292 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenCC is a library for converting characters and phrases between
Traditional Chinese and Simplified Chinese." );
	script_tag( name: "affected", value: "'opencc' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "opencc", rpm: "opencc~1.0.5~3.fc29", rls: "FC29" ) )){
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

