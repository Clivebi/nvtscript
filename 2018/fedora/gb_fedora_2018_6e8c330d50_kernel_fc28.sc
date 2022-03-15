if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875369" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2018-19406", "CVE-2018-19824", "CVE-2018-16862", "CVE-2018-19407", "CVE-2018-18710", "CVE-2018-14633", "CVE-2018-17182", "CVE-2018-5391", "CVE-2018-15471", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-14734", "CVE-2018-14678", "CVE-2018-13405", "CVE-2018-13053", "CVE-2018-12896", "CVE-2018-13093", "CVE-2018-13094", "CVE-2018-13095", "CVE-2018-12714", "CVE-2018-12633", "CVE-2018-12232", "CVE-2018-10853", "CVE-2018-11506", "CVE-2018-10840", "CVE-2018-3639", "CVE-2018-1120", "CVE-2018-10322", "CVE-2018-10323", "CVE-2018-1108", "CVE-2018-14625", "CVE-2018-20169" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-21 12:16:00 +0000 (Tue, 21 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-12-21 07:55:44 +0100 (Fri, 21 Dec 2018)" );
	script_name( "Fedora Update for kernel FEDORA-2018-6e8c330d50" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2018-6e8c330d50" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DYHM2QYFANUFBT6LM2CPW6M7PHBT4XAD" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel'
  package(s) announced via the FEDORA-2018-6e8c330d50 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "kernel on Fedora 28." );
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
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~4.19.10~200.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

