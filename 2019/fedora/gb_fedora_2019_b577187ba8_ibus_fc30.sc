if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876838" );
	script_version( "2021-09-01T10:01:36+0000" );
	script_cve_id( "CVE-2019-14822" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 10:01:36 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-27 15:15:00 +0000 (Thu, 27 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-26 02:31:20 +0000 (Thu, 26 Sep 2019)" );
	script_name( "Fedora Update for ibus FEDORA-2019-b577187ba8" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-b577187ba8" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VG6WEO3ISGPMEC6XSZLK4BZE5GHSF4SM" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ibus'
  package(s) announced via the FEDORA-2019-b577187ba8 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "IBus means Intelligent Input Bus. It is an input framework for Linux OS." );
	script_tag( name: "affected", value: "'ibus' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "ibus", rpm: "ibus~1.5.20~5.fc30", rls: "FC30" ) )){
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

