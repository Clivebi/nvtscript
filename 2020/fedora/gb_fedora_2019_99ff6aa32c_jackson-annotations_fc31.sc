if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877127" );
	script_version( "2021-07-19T02:00:45+0000" );
	script_cve_id( "CVE-2019-12086", "CVE-2019-12384", "CVE-2019-12814", "CVE-2019-14379", "CVE-2019-14439" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-19 02:00:45 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:26:48 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for jackson-annotations FEDORA-2019-99ff6aa32c" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-99ff6aa32c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2ZFZOXSDOGZIDMS4CEJWOWRRM2NOZZRA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jackson-annotations'
  package(s) announced via the FEDORA-2019-99ff6aa32c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Core annotations used for value types,
used by Jackson data-binding package." );
	script_tag( name: "affected", value: "'jackson-annotations' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "jackson-annotations", rpm: "jackson-annotations~2.9.9~1.fc31", rls: "FC31" ) )){
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

