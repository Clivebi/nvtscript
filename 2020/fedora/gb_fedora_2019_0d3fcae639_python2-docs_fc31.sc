if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877114" );
	script_version( "2021-07-15T11:00:44+0000" );
	script_cve_id( "CVE-2018-20852", "CVE-2019-16056", "CVE-2019-16935" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-15 11:00:44 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-22 17:15:00 +0000 (Sat, 22 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:26:34 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for python2-docs FEDORA-2019-0d3fcae639" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-0d3fcae639" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/K7HNVIFMETMFWWWUNTB72KYJYXCZOS5V" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python2-docs'
  package(s) announced via the FEDORA-2019-0d3fcae639 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The python2-docs package contains documentation on the Python 2
programming language and interpreter.

Install the python2-docs package if you&#39, d like to use the documentation
for the Python 2 language." );
	script_tag( name: "affected", value: "'python2-docs' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "python2-docs", rpm: "python2-docs~2.7.17~1.fc31", rls: "FC31" ) )){
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

