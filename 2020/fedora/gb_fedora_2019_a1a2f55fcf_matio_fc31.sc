if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877350" );
	script_version( "2021-07-16T11:00:51+0000" );
	script_cve_id( "CVE-2019-13107" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-16 11:00:51 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-18 21:15:00 +0000 (Thu, 18 Jul 2019)" );
	script_tag( name: "creation_date", value: "2020-01-12 04:01:42 +0000 (Sun, 12 Jan 2020)" );
	script_name( "Fedora Update for matio FEDORA-2019-a1a2f55fcf" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-a1a2f55fcf" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N7AE25FWDBPC7KLVMPLHT4G64O4GISQQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'matio'
  package(s) announced via the FEDORA-2019-a1a2f55fcf advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "matio is an open-source library for reading/writing Matlab MAT files.  This
library is designed for use by programs/libraries that do not have access or
do not want to rely on Matlab&#39, s libmat shared library." );
	script_tag( name: "affected", value: "'matio' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "matio", rpm: "matio~1.5.17~1.fc31", rls: "FC31" ) )){
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

