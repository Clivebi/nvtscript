if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876177" );
	script_version( "2021-09-01T09:01:32+0000" );
	script_cve_id( "CVE-2019-8980", "CVE-2019-8912", "CVE-2019-7221", "CVE-2019-6974", "CVE-2019-7222", "CVE-2018-16880", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-3701", "CVE-2018-19824", "CVE-2018-16862", "CVE-2018-19407", "CVE-2018-18710", "CVE-2019-9162" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 09:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-02 15:32:00 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:37:57 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for kernel FEDORA-2019-7462acf8ba" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-7462acf8ba" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5V6NQPIGUR73VSTY22YLUKTLEB66AA4U" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the FEDORA-2019-7462acf8ba advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The kernel meta package" );
	script_tag( name: "affected", value: "'kernel' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel", rpm: "kernel~4.20.12~200.fc29", rls: "FC29" ) )){
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

