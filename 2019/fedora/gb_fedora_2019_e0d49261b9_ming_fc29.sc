if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875733" );
	script_version( "2021-09-01T14:01:32+0000" );
	script_cve_id( "CVE-2018-6358", "CVE-2018-7867", "CVE-2018-7868", "CVE-2018-7870", "CVE-2018-7871", "CVE-2018-7872", "CVE-2018-7875", "CVE-2018-9165" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 14:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:18:13 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for ming FEDORA-2019-e0d49261b9" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-e0d49261b9" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DCVKRTMEAJTXCYXNA53WZFPDF67TN7NC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ming'
  package(s) announced via the FEDORA-2019-e0d49261b9 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ming is a library for generating Macromedia Flash files (.swf), written in C,
and includes useful utilities for working with .swf files." );
	script_tag( name: "affected", value: "'ming' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "ming", rpm: "ming~0.4.9~0.1.20181112git5009802.fc29", rls: "FC29" ) )){
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

