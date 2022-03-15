if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874649" );
	script_version( "2021-06-10T02:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-10 02:00:20 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-06 10:25:48 +0200 (Wed, 06 Jun 2018)" );
	script_cve_id( "CVE-2018-7419", "CVE-2018-7418", "CVE-2018-7417", "CVE-2018-7420", "CVE-2018-7320", "CVE-2018-7336", "CVE-2018-7337", "CVE-2018-7334", "CVE-2018-7335", "CVE-2018-6836", "CVE-2018-5335", "CVE-2018-5334", "CVE-2017-6014", "CVE-2017-9616", "CVE-2017-9617", "CVE-2017-9766", "CVE-2017-17935", "CVE-2017-17085", "CVE-2017-17084", "CVE-2017-17083", "CVE-2017-15189", "CVE-2017-15190", "CVE-2017-15191", "CVE-2017-15192", "CVE-2017-15193", "CVE-2017-13764", "CVE-2017-13765", "CVE-2017-13766", "CVE-2017-13767", "CVE-2018-11362", "CVE-2018-11361", "CVE-2018-11360", "CVE-2018-11359", "CVE-2018-11358", "CVE-2018-11357", "CVE-2018-11356", "CVE-2018-11355", "CVE-2018-11354" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for wireshark FEDORA-2018-d1cfa444d2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "wireshark on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-d1cfa444d2" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/S4TES6EYI77P55Y77OPJQCCKJKZ7EQBY" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC27" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC27"){
	if(( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~2.6.1~1.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

