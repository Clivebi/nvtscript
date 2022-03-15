if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875564" );
	script_version( "2021-09-01T13:01:35+0000" );
	script_cve_id( "CVE-2019-9844" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 13:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 12:31:00 +0000 (Mon, 15 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-04-17 02:11:39 +0000 (Wed, 17 Apr 2019)" );
	script_name( "Fedora Update for nodejs-simple-markdown FEDORA-2019-8e7c71f45b" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-8e7c71f45b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JFLP3KJVSV5VWMNEBRXLGRVYFXOV5KOG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'nodejs-simple-markdown' package(s) announced via the FEDORA-2019-8e7c71f45b
  advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "simple-markdown is a markdown-like parser
  designed for simplicity and extensibility." );
	script_tag( name: "affected", value: "'nodejs-simple-markdown' package(s) on Fedora 28." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs-simple-markdown", rpm: "nodejs-simple-markdown~0.4.4~1.fc28", rls: "FC28" ) )){
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

