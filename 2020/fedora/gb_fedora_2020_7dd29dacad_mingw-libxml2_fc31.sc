if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878319" );
	script_version( "2021-07-16T02:00:53+0000" );
	script_cve_id( "CVE-2020-24977", "CVE-2019-19956", "CVE-2019-20388", "CVE-2020-7595" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-16 02:00:53 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-06 06:15:00 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-09-20 03:09:13 +0000 (Sun, 20 Sep 2020)" );
	script_name( "Fedora: Security Advisory for mingw-libxml2 (FEDORA-2020-7dd29dacad)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-7dd29dacad" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/H3IQ7OQXBKWD3YP7HO6KCNOMLE5ZO2IR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-libxml2'
  package(s) announced via the FEDORA-2020-7dd29dacad advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MinGW Windows libxml2 XML processing library." );
	script_tag( name: "affected", value: "'mingw-libxml2' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-libxml2", rpm: "mingw-libxml2~2.9.10~3.fc31", rls: "FC31" ) )){
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

