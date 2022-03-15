if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877355" );
	script_version( "2021-07-13T11:00:50+0000" );
	script_cve_id( "CVE-2018-10536", "CVE-2018-10537", "CVE-2018-10538", "CVE-2018-10539", "CVE-2018-10540", "CVE-2018-19840", "CVE-2018-19841", "CVE-2019-11498", "CVE-2019-1010315", "CVE-2019-1010319", "CVE-2019-1010317" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-13 11:00:50 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-20 10:15:00 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2020-01-14 04:03:12 +0000 (Tue, 14 Jan 2020)" );
	script_name( "Fedora Update for mingw-wavpack FEDORA-2020-e55567b6be" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-e55567b6be" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6CFFFWIWALGQPKINRDW3PRGRD5LOLGZA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-wavpack'
  package(s) announced via the FEDORA-2020-e55567b6be advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "WavPack is a completely open audio compression format providing lossless,
high-quality lossy, and a unique hybrid compression mode. Although the
technology is loosely based on previous versions of WavPack, the new
version 4 format has been designed from the ground up to offer unparalleled
performance and functionality." );
	script_tag( name: "affected", value: "'mingw-wavpack' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-wavpack", rpm: "mingw-wavpack~5.1.0~9.fc31", rls: "FC31" ) )){
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

