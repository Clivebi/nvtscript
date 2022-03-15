if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876247" );
	script_version( "2021-09-01T10:01:36+0000" );
	script_cve_id( "CVE-2018-20230", "CVE-2019-9211" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 10:01:36 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:40:31 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for pspp FEDORA-2019-817ff2201f" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-817ff2201f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/O3QC6VFE2D7M6ZJXBXRIO4JZPKY57CLV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pspp'
  package(s) announced via the FEDORA-2019-817ff2201f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "PSPP is a program for statistical analysis of sampled data. It
interprets commands in the SPSS language and produces tabular
output in ASCII, PostScript, or HTML format.

PSPP development is ongoing. It already supports a large subset
of SPSS&#39, s transformation language. Its statistical procedure
support is currently limited, but growing." );
	script_tag( name: "affected", value: "'pspp' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "pspp", rpm: "pspp~1.2.0~2.fc29", rls: "FC29" ) )){
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

